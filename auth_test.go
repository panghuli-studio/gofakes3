package gofakes3_test

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/OpenListTeam/gofakes3"
	"github.com/OpenListTeam/gofakes3/signature"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// signedGet makes a GET / request to url signed with the credentials given
// and returns the status code.
func signedGet(t *testing.T, url, accessKey, secretKey string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	creds := aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
	err = v4.NewSigner().SignHTTP(context.Background(), creds, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestAuthKeysPerInstance checks that the keys added to one GoFakeS3
// instance are not accepted by another instance in the same process.
func TestAuthKeysPerInstance(t *testing.T) {
	tsA := newTestServer(t, withFakerOptions(gofakes3.WithV4Auth(map[string]string{"KEYA": "SECRETA"})))
	defer tsA.Close()
	tsB := newTestServer(t, withFakerOptions(gofakes3.WithV4Auth(map[string]string{"KEYB": "SECRETB"})))
	defer tsB.Close()

	for _, tc := range []struct {
		name      string
		url       string
		accessKey string
		secretKey string
		want      int
	}{
		{"A with A's key", tsA.server.URL, "KEYA", "SECRETA", http.StatusOK},
		{"B with B's key", tsB.server.URL, "KEYB", "SECRETB", http.StatusOK},
		{"A with B's key", tsA.server.URL, "KEYB", "SECRETB", http.StatusForbidden},
		{"B with A's key", tsB.server.URL, "KEYA", "SECRETA", http.StatusForbidden},
		{"A with wrong secret", tsA.server.URL, "KEYA", "SECRETB", http.StatusForbidden},
		{"A with unknown key", tsA.server.URL, "KEYC", "SECRETC", http.StatusForbidden},
	} {
		if got := signedGet(t, tc.url, tc.accessKey, tc.secretKey); got != tc.want {
			t.Errorf("%s: got status %d, want %d", tc.name, got, tc.want)
		}
	}

	// Keys added and removed later are also per instance
	tsA.AddAuthKeys(map[string]string{"KEYC": "SECRETC"})
	if got := signedGet(t, tsA.server.URL, "KEYC", "SECRETC"); got != http.StatusOK {
		t.Errorf("A with added key: got status %d, want 200", got)
	}
	if got := signedGet(t, tsB.server.URL, "KEYC", "SECRETC"); got != http.StatusForbidden {
		t.Errorf("B with key added to A: got status %d, want 403", got)
	}
	tsA.DelAuthKeys([]string{"KEYC"})
	if got := signedGet(t, tsA.server.URL, "KEYC", "SECRETC"); got != http.StatusForbidden {
		t.Errorf("A with removed key: got status %d, want 403", got)
	}
	// Removing a key from A must not affect B's keys
	if got := signedGet(t, tsB.server.URL, "KEYB", "SECRETB"); got != http.StatusOK {
		t.Errorf("B with B's key after A removed a key: got status %d, want 200", got)
	}
}

// v2HeaderRequest builds a GET / request authenticated with a header-based
// Signature V2 credential. The Date header is part of the string to sign, so it
// has to be set before signing.
func v2HeaderRequest(t *testing.T, url, accessKey, secretKey string, date time.Time) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Date", date.UTC().Format(http.TimeFormat))
	creds := signature.CredentialsV2{AccessKey: accessKey, SecretKey: secretKey}
	req.Header.Set("Authorization", "AWS "+accessKey+":"+creds.SignV2(req.Method, req.URL.Path, req.URL.RawQuery, req.Header, ""))
	return req
}

// TestAuthV2HeaderCredential checks that header-based Signature V2 credentials
// are accepted, and that a stale Date is refused. Signature V2 signs the date
// but carries no expiry of its own, so without the freshness check a captured
// Authorization header would stay replayable forever.
func TestAuthV2HeaderCredential(t *testing.T) {
	ts := newTestServer(t, withFakerOptions(gofakes3.WithV4Auth(map[string]string{"KEYA": "SECRETA"})))
	defer ts.Close()

	// errExpiredRequest, which both failures below come from, is not exported, so
	// pin the status the error table maps it to.
	expiredStatus := http.StatusBadRequest

	for _, tc := range []struct {
		name      string
		accessKey string
		secretKey string
		date      time.Time
		want      int
	}{
		{"fresh", "KEYA", "SECRETA", time.Now(), http.StatusOK},
		{"stale date", "KEYA", "SECRETA", time.Now().Add(-time.Hour), expiredStatus},
		{"wrong secret", "KEYA", "SECRETB", time.Now(), http.StatusForbidden},
		{"unknown key", "KEYC", "SECRETC", time.Now(), http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.DefaultClient.Do(v2HeaderRequest(t, ts.server.URL, tc.accessKey, tc.secretKey, tc.date))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

// TestAuthV2QueryCredential checks the query-string form of Signature V2, which
// is the form presigned URLs use: Expires is an absolute Unix timestamp.
func TestAuthV2QueryCredential(t *testing.T) {
	ts := newTestServer(t, withFakerOptions(gofakes3.WithV4Auth(map[string]string{"KEYA": "SECRETA"})))
	defer ts.Close()

	expiredStatus := http.StatusBadRequest

	newRequest := func(expires time.Time) *http.Request {
		t.Helper()
		expiresStr := strconv.FormatInt(expires.Unix(), 10)
		// None of AWSAccessKeyId/Expires/Signature belongs to the V2 canonical
		// sub-resource whitelist, so the signed resource is just the path.
		creds := signature.CredentialsV2{AccessKey: "KEYA", SecretKey: "SECRETA"}
		signed := creds.SignV2(http.MethodGet, "/", "", http.Header{}, expiresStr)
		query := url.Values{}
		query.Set("AWSAccessKeyId", "KEYA")
		query.Set("Expires", expiresStr)
		query.Set("Signature", signed)
		req, err := http.NewRequest(http.MethodGet, ts.server.URL+"/?"+query.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	for _, tc := range []struct {
		name    string
		expires time.Time
		want    int
	}{
		{"not expired", time.Now().Add(time.Hour), http.StatusOK},
		{"expired", time.Now().Add(-time.Hour), expiredStatus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.DefaultClient.Do(newRequest(tc.expires))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}
