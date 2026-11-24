package gofakes3

import (
	"bytes"
	"strings"
	"testing"

	xml "github.com/minio/xxml"
)

func TestInitiateMultipartUploadRootElement(t *testing.T) {
	var buf bytes.Buffer
	if err := xml.NewEncoder(&buf).Encode(InitiateMultipartUpload{Bucket: "b", Key: "k", UploadID: "id"}); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.HasPrefix(got, "<InitiateMultipartUploadResult>") || !strings.Contains(got, "<UploadId>id</UploadId>") {
		t.Fatalf("encoded = %s, want an InitiateMultipartUploadResult root with UploadId", got)
	}
}
