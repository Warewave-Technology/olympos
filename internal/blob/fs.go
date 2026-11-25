package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/Warewave-Technology/olympos/internal/store"
)

// File suffixes used by the filesystem (NFS) writer.
const (
	// TagsSuffix: tags of <file> are stored as JSON in <file>.tags.json
	// (filesystems have no object tags; retention scripts / storage
	// policies can read them).
	TagsSuffix    = ".tags.json"
	partialSuffix = ".partial"
	dirPerm       = 0o750
	filePerm      = 0o640
)

// Mount is a volume below the NFS root that NFS destinations may use.
type Mount struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Writable bool   `json:"writable"`
}

// ListMounts returns the first-level subdirectories of root (hidden names
// and symlinks are skipped: a mount is a real directory). A missing root
// means no mounts.
func ListMounts(root string) ([]Mount, error) {
	if root == "" {
		root = DefaultNFSRoot
	}
	ents, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return []Mount{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Mount{}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") || e.Type()&fs.ModeSymlink != 0 || !e.IsDir() {
			continue
		}
		p := filepath.Join(root, e.Name())
		out = append(out, Mount{Name: e.Name(), Path: p, Writable: writable(p)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func writable(p string) bool { return unix.Access(p, unix.W_OK) == nil }

// within reports whether p is base or below it (both cleaned, absolute).
func within(base, p string) bool {
	rel, err := filepath.Rel(base, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// evalExisting resolves symlinks in the longest existing ancestor of p and
// appends the not-yet-existing rest.
func evalExisting(p string) (string, error) {
	rest := []string{}
	cur := p
	for {
		ev, err := filepath.EvalSymlinks(cur)
		if err == nil {
			for i := len(rest) - 1; i >= 0; i-- {
				ev = filepath.Join(ev, rest[i])
			}
			return ev, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", err
		}
		rest = append(rest, filepath.Base(cur))
		cur = parent
	}
}

// ResolveFSPath checks that p (absolute) is a directory inside one of the
// mounts below root, after filepath.Clean and symlink evaluation of the part
// that exists. It returns the resolved path, the mount and the mount's
// resolved path. ".." segments are rejected outright.
func ResolveFSPath(root, p string) (resolved string, m Mount, mountDir string, err error) {
	if root == "" {
		root = DefaultNFSRoot
	}
	if !filepath.IsAbs(p) {
		return "", Mount{}, "", fmt.Errorf("must be an absolute path below %s/<mount>", root)
	}
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return "", Mount{}, "", errors.New("must not contain '..'")
		}
	}
	clean := filepath.Clean(p)
	root = filepath.Clean(root)
	rel, err := filepath.Rel(root, clean)
	if err != nil || rel == "." || !within(root, clean) {
		return "", Mount{}, "", fmt.Errorf("must be inside a mount below %s (see the mounts list)", root)
	}
	name := strings.Split(filepath.ToSlash(rel), "/")[0]
	mp := filepath.Join(root, name)
	st, err := os.Lstat(mp)
	if err != nil || !st.IsDir() || strings.HasPrefix(name, ".") {
		return "", Mount{}, "", fmt.Errorf("%s is not a mounted volume (see the mounts list)", mp)
	}
	mountEval, err := filepath.EvalSymlinks(mp)
	if err != nil {
		return "", Mount{}, "", fmt.Errorf("mount %s: %w", name, err)
	}
	ev, err := evalExisting(clean)
	if err != nil {
		return "", Mount{}, "", fmt.Errorf("resolve %s: %w", clean, err)
	}
	if !within(mountEval, ev) {
		return "", Mount{}, "", fmt.Errorf("%s resolves to %s, outside mount %s (symlink escape)", clean, ev, name)
	}
	return ev, Mount{Name: name, Path: mp, Writable: writable(mp)}, mountEval, nil
}

// FSTarget is an nfs destinations row.
type FSTarget struct {
	Name   string
	Path   string // absolute, below a mount
	Prefix string
}

// FS writes files below one directory of a mounted volume. It implements
// Writer and the probe operations used by the destination test. Unlike
// object storage, the server process technically CAN delete files there;
// it has no code path that does (except probe files and its own .partial
// files of a failed upload), and retention protection must come from the
// storage (snapshots, WORM).
type FS struct {
	dir      string // resolved destination directory
	mountDir string // resolved mount directory
	mount    Mount
	prefix   string
}

var _ Writer = (*FS)(nil)

// OpenFS resolves t.Path below opts.NFSRoot. The directory need not exist
// yet (Upload creates it).
func OpenFS(t FSTarget, opts StorageOptions) (*FS, error) {
	dir, m, mountDir, err := ResolveFSPath(opts.nfsRoot(), t.Path)
	if err != nil {
		return nil, fmt.Errorf("destination path %s", err)
	}
	return &FS{dir: dir, mountDir: mountDir, mount: m, prefix: strings.Trim(t.Prefix, "/")}, nil
}

// Prefix implements Writer.
func (f *FS) Prefix() string { return f.prefix }

// Mount returns the mount the destination lives on.
func (f *FS) Mount() Mount { return f.mount }

// Dir returns the resolved destination directory.
func (f *FS) Dir() string { return f.dir }

// EnsureDir creates the destination directory when missing and checks that
// it is writable. created reports whether it had to be created.
func (f *FS) EnsureDir() (created bool, err error) {
	st, err := os.Stat(f.dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(f.dir, dirPerm); err != nil {
			return false, err
		}
		created = true
	case err != nil:
		return false, err
	case !st.IsDir():
		return false, fmt.Errorf("%s is not a directory", f.dir)
	}
	if _, err := f.safeDir(f.dir); err != nil {
		return created, err
	}
	if !writable(f.dir) {
		return created, fmt.Errorf("%s is not writable by the server (uid %d, gid %d)", f.dir, os.Getuid(), os.Getgid())
	}
	return created, nil
}

// safeDir resolves symlinks of an existing directory and checks it is still
// inside the mount (a symlink created on the export later must not let a
// write escape).
func (f *FS) safeDir(d string) (string, error) {
	ev, err := filepath.EvalSymlinks(d)
	if err != nil {
		return "", err
	}
	if !within(f.mountDir, ev) {
		return "", fmt.Errorf("%s resolves outside mount %s (symlink escape)", d, f.mount.Name)
	}
	return ev, nil
}

// file maps a blob path to its resolved file path, creating parent dirs
// (0750) when mkdir is set.
func (f *FS) file(path string, mkdir bool) (string, error) {
	if err := validPath(path); err != nil {
		return "", err
	}
	if strings.HasSuffix(path, partialSuffix) || strings.HasSuffix(path, TagsSuffix) {
		return "", fmt.Errorf("invalid path %q: reserved suffix", path)
	}
	full := filepath.Join(f.dir, filepath.FromSlash(path))
	parent := filepath.Dir(full)
	if mkdir {
		if err := os.MkdirAll(parent, dirPerm); err != nil {
			return "", err
		}
	}
	ev, err := f.safeDir(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(ev, filepath.Base(full)), nil
}

// publish moves a fully written, fsynced partial file to final without ever
// replacing an existing file: link(2) fails with EEXIST atomically. On
// filesystems without hard links it falls back to an existence check plus
// rename(2) (not atomic; keys contain the run ID, so a race is a bug).
func publish(partial, final string) error {
	err := os.Link(partial, final)
	switch {
	case err == nil:
		return os.Remove(partial)
	case errors.Is(err, fs.ErrExist):
		_ = os.Remove(partial)
		return fmt.Errorf("%s already exists; refusing to overwrite", filepath.Base(final))
	}
	if _, serr := os.Lstat(final); serr == nil {
		_ = os.Remove(partial)
		return fmt.Errorf("%s already exists; refusing to overwrite", filepath.Base(final))
	}
	return os.Rename(partial, final)
}

// writeExclusive writes r to final via final.partial (O_EXCL, 0640),
// fsync and publish. It returns bytes and sha256.
func writeExclusive(final string, r io.Reader) (int64, string, error) {
	if _, err := os.Lstat(final); err == nil {
		return 0, "", fmt.Errorf("%s already exists; refusing to overwrite", filepath.Base(final))
	}
	partial := final + partialSuffix
	fh, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return 0, "", fmt.Errorf("%s exists (another upload in progress or a stale partial file)", filepath.Base(partial))
		}
		return 0, "", err
	}
	hr := &hashingReader{r: r, h: sha256.New()}
	buf := make([]byte, 1<<20)
	_, err = io.CopyBuffer(fh, hr, buf)
	if err == nil {
		err = fh.Sync()
	}
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(partial) // our own incomplete file, never a backup
		return 0, "", err
	}
	if err := publish(partial, final); err != nil {
		return 0, "", err
	}
	return hr.n, hex.EncodeToString(hr.h.Sum(nil)), nil
}

func syncDir(d string) {
	if fh, err := os.Open(d); err == nil {
		_ = fh.Sync()
		_ = fh.Close()
	}
}

// Upload implements Writer: <file>.partial (O_EXCL, 0640) → fsync → link to
// <file> (never overwrites) → fsync of the directory. tags go to
// <file>.tags.json the same way.
func (f *FS) Upload(ctx context.Context, path string, r io.Reader, contentType string, tags map[string]string) (UploadResult, error) {
	final, err := f.file(path, true)
	if err != nil {
		return UploadResult{}, fmt.Errorf("upload %s: %w", path, err)
	}
	n, sum, err := writeExclusive(final, ctxReader{ctx, r})
	if err != nil {
		return UploadResult{}, fmt.Errorf("upload %s: %w", path, err)
	}
	if len(tags) > 0 {
		b, _ := json.Marshal(tags)
		if _, _, err := writeExclusive(final+TagsSuffix, bytes.NewReader(b)); err != nil {
			return UploadResult{}, fmt.Errorf("upload %s: write tags: %w", path, err)
		}
	}
	syncDir(filepath.Dir(final))
	return UploadResult{Bytes: n, SHA256: sum}, nil
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// Download reads at most max bytes of a file (probe/manifest use only).
func (f *FS) Download(ctx context.Context, path string, max int64) ([]byte, error) {
	p, err := f.file(path, false)
	if err != nil {
		return nil, err
	}
	fh, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return io.ReadAll(io.LimitReader(fh, max))
}

// SetTags replaces the tags sidecar of a probe file, or of an object of a
// native run (IsNativeRunObject), which is tagged complete once the run's
// manifest is signed. The file must exist, and only its sidecar changes.
// Every other backup keeps the tags Upload wrote once.
func (f *FS) SetTags(ctx context.Context, path string, tags map[string]string) error {
	if !IsProbePath(path) && !IsNativeRunObject(path) {
		return fmt.Errorf("refusing to rewrite tags of %q: only probe files and the objects of native runs", path)
	}
	p, err := f.file(path, false)
	if err != nil {
		return err
	}
	if st, err := os.Lstat(p); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("refusing to tag %q: not a stored file", path)
	}
	b, _ := json.Marshal(tags)
	tmp := p + TagsSuffix + "." + uuid.NewString()[:8] + partialSuffix
	if err := os.WriteFile(tmp, b, filePerm); err != nil {
		return err
	}
	if err := os.Rename(tmp, p+TagsSuffix); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// IsNativeRunObject reports whether path is an object inside a native run's
// directory: a segment before the last is a run ID, a canonical lower-case
// UUID (<…>/<run-id>/<key>). A logical backup is a file named after its run
// (<run-id>.<ext>), not inside a directory of it.
func IsNativeRunObject(path string) bool {
	segs := strings.Split(path, "/")
	for _, s := range segs[:len(segs)-1] {
		if u, err := uuid.Parse(s); err == nil && u.String() == s {
			return true
		}
	}
	return false
}

// GetTags reads the tags sidecar (empty when there is none).
func (f *FS) GetTags(ctx context.Context, path string) (map[string]string, error) {
	p, err := f.file(path, false)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p + TagsSuffix)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("invalid tags file: %w", err)
	}
	return out, nil
}

// ProbeDeleteRefused attempts to delete a probe file (and its tags
// sidecar). On a normal filesystem this succeeds (refused=false: the server
// can delete there). EACCES/EPERM/EROFS (WORM, immutable attributes, a
// read-only snapshot policy) count as refused. Only ProbeDir paths.
func (f *FS) ProbeDeleteRefused(ctx context.Context, path string) (refused bool, err error) {
	if !IsProbePath(path) {
		return false, fmt.Errorf("refusing to delete %q: only probe files under %s/ may be touched", path, ProbeDir)
	}
	p, err := f.file(path, false)
	if err != nil {
		return false, err
	}
	err = os.Remove(p)
	switch {
	case err == nil:
		_ = os.Remove(p + TagsSuffix)
		return false, nil
	case errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS) || errors.Is(err, syscall.EPERM):
		return true, nil
	}
	return false, err
}

// LoadFSTarget reads an nfs destinations row.
func LoadFSTarget(ctx context.Context, q store.Querier, id uuid.UUID) (FSTarget, error) {
	var t FSTarget
	var kind string
	err := q.QueryRow(ctx, `SELECT kind, name, path, prefix FROM destinations WHERE id = $1`, id).Scan(&kind, &t.Name, &t.Path, &t.Prefix)
	if err != nil {
		return FSTarget{}, fmt.Errorf("load destination: %w", store.NotFound(err))
	}
	if kind != KindNFS {
		return FSTarget{}, fmt.Errorf("destination %q is of kind %s, not %s", t.Name, kind, KindNFS)
	}
	return t, nil
}

var _ Reader = (*FS)(nil)

// Open implements Reader over the safe resolved path of a regular file.
func (f *FS) Open(ctx context.Context, path string) (Object, error) {
	p, err := f.file(path, false)
	if err != nil {
		return nil, err
	}
	// file resolved the directory; resolve the last component too so a
	// symlink in the destination cannot point outside the mount.
	if p, err = f.safeDir(p); err != nil {
		return nil, err
	}
	fh, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	st, err := fh.Stat()
	if err != nil {
		_ = fh.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		_ = fh.Close()
		return nil, fmt.Errorf("open %s: not a regular file", path)
	}
	return &fsObject{ctx: ctx, f: fh, size: st.Size()}, nil
}
