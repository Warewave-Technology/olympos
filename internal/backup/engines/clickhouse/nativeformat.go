package clickhouse

// Streaming ClickHouse data as "FORMAT Native" over the native protocol.
//
// Over the native TCP protocol the FORMAT clause of a SELECT is a client-side
// concern: the server always answers with Data packets carrying blocks
// (clickhouse-client is what turns them into the Native file format). So we
// cannot ask the server for raw "FORMAT Native" bytes on port 9000/9440 the
// way the HTTP interface would return them.
//
// Approach: we use github.com/ClickHouse/ch-go, which exposes the protocol
// block by block (zstd network compression, custom net.Conn). nativeResult
// is a proto.Result that decodes each incoming block into ch-go columns
// (types inferred from the block header via proto.ColAuto) and
// writeNativeBlock re-encodes it immediately in the Native *format* layout:
//
//	varuint columns, varuint rows,
//	per column: String name, String type, [serialization state prefix], data
//
// This is exactly the layout ClickHouse's NativeWriter emits for
// "FORMAT Native" (client revision 0: no BlockInfo, no custom-serialization
// flag), so the files load with `INSERT INTO t FORMAT Native`. The column
// data serialization is ClickHouse's own binary column encoding, which ch-go
// reproduces byte-compatibly; only one block (default max_block_size rows) is
// held in memory at a time, giving natural back-pressure from the Blob writer
// to the socket.
//
// The type string written into the file is the one the server sent (not
// ch-go's normalized type), so parameters such as Enum values, DateTime
// time zones and Decimal scales are preserved verbatim.
//
// Types ch-go cannot decode (Tuple, most Map variants, AggregateFunction,
// Variant/Dynamic/JSON, LowCardinality(Nullable(...)), Nested, ...) are
// detected up front from system.columns. Such tables fall back to
// RowBinaryWithNamesAndTypes: the server serializes each row with
// formatRowNoNewline('RowBinary', *) (server-side, so every type including
// aggregate function states is supported), the client concatenates the rows
// behind a names-and-types header. See engine.go (streamRowBinary).

import (
	"errors"
	"fmt"
	"io"

	"github.com/ClickHouse/ch-go/proto"
)

// protocolVersion is the native protocol revision we announce. It is kept
// below FeatureCustomSerialization (54454) defensively: a client of that
// revision can never be sent sparse/custom column serializations, which
// ch-go cannot decode and which the Native file format (revision 0) cannot
// carry. (24.8 already materializes sparse columns in SELECT results; the
// integration test covers a table with sparse parts.) Nothing we use needs
// a newer revision.
const protocolVersion = 54453

// nativeSupported reports whether ch-go can decode (and re-encode) type t.
func nativeSupported(t string) bool {
	var c proto.ColAuto
	return c.Infer(proto.ColumnType(t)) == nil
}

type nativeColumn struct {
	name string
	typ  string
	data proto.Column
}

// nativeResult decodes blocks into columns inferred from the first header.
type nativeResult struct {
	cols []nativeColumn
	rows int
}

var _ proto.Result = (*nativeResult)(nil)

func (r *nativeResult) DecodeResult(rd *proto.Reader, version int, b proto.Block) error {
	first := r.cols == nil
	if !first && b.Columns != len(r.cols) {
		return fmt.Errorf("block has %d columns, expected %d", b.Columns, len(r.cols))
	}
	if first {
		r.cols = make([]nativeColumn, 0, b.Columns)
	}
	r.rows = 0
	for i := 0; i < b.Columns; i++ {
		name, err := rd.Str()
		if err != nil {
			return fmt.Errorf("column %d name: %w", i, err)
		}
		typ, err := rd.Str()
		if err != nil {
			return fmt.Errorf("column %d type: %w", i, err)
		}
		if proto.FeatureCustomSerialization.In(version) {
			custom, err := rd.Bool()
			if err != nil {
				return fmt.Errorf("column %q serialization flag: %w", name, err)
			}
			if custom {
				return fmt.Errorf("column %q uses a custom serialization (unsupported)", name)
			}
		}
		if first {
			var auto proto.ColAuto
			if err := auto.Infer(proto.ColumnType(typ)); err != nil {
				return fmt.Errorf("column %q: type %s: %w", name, typ, errUnsupportedType)
			}
			r.cols = append(r.cols, nativeColumn{name: name, typ: typ, data: auto.Data})
		} else if r.cols[i].name != name || r.cols[i].typ != typ {
			return fmt.Errorf("column %d changed from %s %s to %s %s", i, r.cols[i].name, r.cols[i].typ, name, typ)
		}
		c := r.cols[i].data
		c.Reset()
		if b.Rows == 0 {
			continue
		}
		if s, ok := c.(proto.StateDecoder); ok {
			if err := s.DecodeState(rd); err != nil {
				return fmt.Errorf("column %q state: %w", name, err)
			}
		}
		if err := c.DecodeColumn(rd, b.Rows); err != nil {
			return fmt.Errorf("column %q: %w", name, err)
		}
	}
	r.rows = b.Rows
	return nil
}

var errUnsupportedType = errors.New("type not supported by the native block codec")

// writeNativeBlock encodes the current block of r in Native format into w.
// buf is reused between calls.
func writeNativeBlock(w io.Writer, buf *proto.Buffer, r *nativeResult) error {
	buf.Reset()
	buf.PutInt(len(r.cols))
	buf.PutInt(r.rows)
	for _, c := range r.cols {
		if c.data.Rows() != r.rows {
			return fmt.Errorf("column %q has %d rows, expected %d", c.name, c.data.Rows(), r.rows)
		}
		buf.PutString(c.name)
		buf.PutString(c.typ)
		if r.rows == 0 {
			continue
		}
		if p, ok := c.data.(proto.Preparable); ok {
			if err := p.Prepare(); err != nil {
				return fmt.Errorf("prepare %q: %w", c.name, err)
			}
		}
		if s, ok := c.data.(proto.StateEncoder); ok {
			s.EncodeState(buf)
		}
		c.data.EncodeColumn(buf)
	}
	_, err := w.Write(buf.Buf)
	return err
}

// stringColumn returns row values of column i when it is a String (or
// LowCardinality(String)) column.
func (r *nativeResult) stringColumn(i int) ([]string, error) {
	if i >= len(r.cols) {
		return nil, fmt.Errorf("result has %d columns, want column %d", len(r.cols), i)
	}
	s, ok := r.cols[i].data.(interface {
		Rows() int
		Row(int) string
	})
	if !ok {
		return nil, fmt.Errorf("column %q is %s, want String", r.cols[i].name, r.cols[i].typ)
	}
	out := make([]string, s.Rows())
	for j := range out {
		out[j] = s.Row(j)
	}
	return out, nil
}

// rowBinaryHeader writes the RowBinaryWithNamesAndTypes header.
func rowBinaryHeader(w io.Writer, names, types []string) error {
	var buf proto.Buffer
	buf.PutInt(len(names))
	for _, n := range names {
		buf.PutString(n)
	}
	for _, t := range types {
		buf.PutString(t)
	}
	_, err := w.Write(buf.Buf)
	return err
}
