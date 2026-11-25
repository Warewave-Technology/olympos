package ingest

import (
	"encoding/xml"
	"net/http"
	"strconv"
)

// The S3 XML bodies the handler reads and writes.

const s3Namespace = "http://s3.amazonaws.com/doc/2006-03-01/"

// s3Error is a reply with an S3 error body. Every deliberate refusal is a 403,
// which ClickHouse does not retry on List; a body that does not match its
// digest is a 400, and the session is stopped as well.
type s3Error struct {
	status  int
	code    string
	message string
}

func (e *s3Error) Error() string { return e.code + ": " + e.message }

func denied(message string) *s3Error {
	return &s3Error{http.StatusForbidden, "AccessDenied", message}
}

func refused(code, message string) *s3Error {
	return &s3Error{http.StatusForbidden, code, message}
}

var (
	errNoSuchKey    = &s3Error{http.StatusNotFound, "NoSuchKey", "The specified key does not exist."}
	errNoSuchUpload = refused("NoSuchUpload", "The specified multipart upload does not exist.")
	errStopped      = denied("The run was stopped.")
	errSHA256       = &s3Error{http.StatusBadRequest, "XAmzContentSHA256Mismatch",
		"The provided 'x-amz-content-sha256' header does not match what was computed."}
	errBadDigest  = &s3Error{http.StatusBadRequest, "BadDigest", "The Content-MD5 you specified did not match what we received."}
	errIncomplete = &s3Error{http.StatusBadRequest, "IncompleteBody", "The body ended before its declared length."}
	errSlowDown   = refused("SlowDown", "Too many requests for this run.")
)

type errorBody struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string
	Message   string
	Resource  string
	RequestID string `xml:"RequestId"`
}

type listBucketResult struct {
	XMLName     xml.Name `xml:"ListBucketResult"`
	Xmlns       string   `xml:"xmlns,attr"`
	Name        string
	Prefix      string
	Marker      string
	NextMarker  string `xml:",omitempty"`
	MaxKeys     int
	IsTruncated bool
	Contents    []listEntry
}

type listEntry struct {
	Key          string
	LastModified string
	ETag         string `xml:",omitempty"`
	Size         int64
	StorageClass string
}

type initiateResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Xmlns    string   `xml:"xmlns,attr"`
	Bucket   string
	Key      string
	UploadID string `xml:"UploadId"`
}

// completeRequest is the body of CompleteMultipartUpload. A tag without a
// namespace matches any, so the S3 namespace is accepted.
type completeRequest struct {
	XMLName xml.Name `xml:"CompleteMultipartUpload"`
	Parts   []struct {
		PartNumber int
		ETag       string
	} `xml:"Part"`
}

type completeResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	Xmlns    string   `xml:"xmlns,attr"`
	Location string
	Bucket   string
	Key      string
	ETag     string
}

// writeXML writes v as the reply's XML body.
func writeXML(w http.ResponseWriter, status int, v any) {
	b, err := xml.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	b = append([]byte(xml.Header), b...)
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeError(w http.ResponseWriter, e *s3Error, resource, requestID string) {
	writeXML(w, e.status, errorBody{Code: e.code, Message: e.message, Resource: resource, RequestID: requestID})
}
