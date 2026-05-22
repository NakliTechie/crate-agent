// SPDX-License-Identifier: AGPL-3.0-or-later
package httpc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSetDeviceIDPropagatesHeader proves that SetDeviceID causes every
// authenticated request to carry an X-Fabric-Device-Id header matching
// the configured value. The Hub's strict caveat-binding mode rejects a
// request whose `device-id == X` caveat is unaccompanied by this header
// (private-mesh PR #5); the daemon's correctness depends on it being set
// consistently on every code path.
func TestSetDeviceIDPropagatesHeader(t *testing.T) {
	const wantDeviceID = "01JDEVICETESTHTTPC00000001"

	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Fabric-Device-Id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.SetDeviceID(wantDeviceID)
	if _, err := c.PostJSONAuth(context.Background(), "/anything", map[string]string{"k": "v"}, "cap"); err != nil {
		t.Fatalf("PostJSONAuth: %v", err)
	}
	if got != wantDeviceID {
		t.Errorf("X-Fabric-Device-Id: got %q, want %q", got, wantDeviceID)
	}
}

// TestDeviceIDOmittedWhenUnset asserts the default behavior preserves
// backward compat: without SetDeviceID, no X-Fabric-Device-Id header is
// added. This matters because the Hub's lax mode (the current default
// in private-mesh) tolerates the omission — sending an empty header
// would still satisfy the caveat but is sloppy.
func TestDeviceIDOmittedWhenUnset(t *testing.T) {
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["X-Fabric-Device-Id"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	if _, err := c.PostJSONAuth(context.Background(), "/anything", map[string]string{"k": "v"}, "cap"); err != nil {
		t.Fatalf("PostJSONAuth: %v", err)
	}
	if present {
		t.Errorf("X-Fabric-Device-Id was set without SetDeviceID; should be absent")
	}
}

// TestDeviceIDSetOnObjectMethods checks every authenticated object-proxy
// method threads through setAuthHeaders, not a bare req.Header.Set. If a
// future contributor regresses any one of them, this test fails.
func TestDeviceIDSetOnObjectMethods(t *testing.T) {
	const wantDeviceID = "01JDEVICETESTOBJ0000000001"
	type call struct {
		method string
		path   string
		header string
	}
	var calls []call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, call{
			method: r.Method,
			path:   r.URL.Path,
			header: r.Header.Get("X-Fabric-Device-Id"),
		})
		w.Header().Set("ETag", `"x"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.SetDeviceID(wantDeviceID)
	ctx := context.Background()

	if _, err := c.PutObject(ctx, "bkt", "p.bin", strings.NewReader("body"), 4, "", "cap"); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if _, err := c.HeadObject(ctx, "bkt", "p.bin", "cap"); err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	if _, err := c.DeleteObject(ctx, "bkt", "p.bin", "cap"); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	if _, err := c.GetObject(ctx, "bkt", "p.bin", "cap"); err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if _, err := c.ListObjects(ctx, "bkt", "", "", "cap"); err != nil {
		t.Fatalf("ListObjects: %v", err)
	}

	if len(calls) != 5 {
		t.Fatalf("expected 5 calls, got %d", len(calls))
	}
	for _, c := range calls {
		if c.header != wantDeviceID {
			t.Errorf("%s %s missing X-Fabric-Device-Id: got %q, want %q", c.method, c.path, c.header, wantDeviceID)
		}
	}
}
