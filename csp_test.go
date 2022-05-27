package csp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/justinas/alice"
	"github.com/pilu/xrequestid"
	"github.com/stretchr/testify/require"
	"github.com/urfave/negroni"
)

func TestHandlerNoPolicy(t *testing.T) {
	csp := New(Config{})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	if header != "" {
		t.Log(header)
		t.Error("expected header to be empty")
	}
}

func TestHandlerDefaultPolicy(t *testing.T) {
	csp := New(Config{
		Default: []string{None},
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	require.Equal(t, "default-src 'none';", header)
}

func TestHandlerScriptPolicy(t *testing.T) {
	csp := New(Config{
		Script: []string{Self},
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	require.Equal(t, " script-src 'self';", header)
}

func TestHandlerConnect(t *testing.T) {
	csp := New(Config{
		Connect: []string{Self},
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	require.Equal(t, " connect-src 'self';", header)
}

func TestHandlerConnectWebSocket(t *testing.T) {
	csp := New(Config{
		Connect:   []string{Self},
		WebSocket: true,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get("Content-Security-Policy")
	require.Equal(t, " connect-src 'self' ws://localhost:3000;", header)
}

func TestHandlerConnectWebSocketDuplicateHeader(t *testing.T) {
	csp := New(Config{
		Connect:   []string{Self},
		WebSocket: true,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	require.Equal(t, " connect-src 'self' ws://localhost:3000;", header)

	r = &http.Request{}
	r.Host = "localhost:3000"
	rw = httptest.NewRecorder()
	fn(rw, r)
	header = rw.Header().Get("Content-Security-Policy")
	require.Equal(t, " connect-src 'self' ws://localhost:3000;", header)
}

func TestHandlerConnectTLSWebSocket(t *testing.T) {
	csp := New(Config{
		Connect:   []string{Self},
		WebSocket: true,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.TLS = &tls.ConnectionState{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	require.Equal(t, " connect-src 'self' wss://localhost:3000;", header)
}

func TestHandlerConnectTLSWebSocketWithHostOverwrittenInContext(t *testing.T) {
	hp := func(ctx context.Context) string {
		// naive
		return ctx.Value("originalHost").(string)
	}

	csp := New(Config{
		Connect:   []string{Self},
		WebSocket: true,
	}).WithHostProvider(hp)
	fn := csp.HandlerFunc()

	ctx := context.WithValue(context.Background(), "originalHost", "example.com")
	rw := httptest.NewRecorder()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "localhost:3000", nil)
	require.NoError(t, err)
	r.TLS = &tls.ConnectionState{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	require.Equal(t, " connect-src 'self' wss://example.com;", header)
}

func TestHandlerConnectTLSWebSocketWithHostOverwrittenInContextEmpty(t *testing.T) {
	hp := func(ctx context.Context) string {
		// naive
		return ctx.Value(12312).(string)
	}
	csp := New(Config{
		Connect:   []string{Self},
		WebSocket: true,
	}).WithHostProvider(hp)
	fn := csp.HandlerFunc()

	ctx := context.WithValue(context.Background(), 12312, "")
	rw := httptest.NewRecorder()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "localhost:3000", nil)
	require.NoError(t, err)
	r.TLS = &tls.ConnectionState{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	require.Equal(t, " connect-src 'self' wss://localhost:3000;", header)
}

func TestHandlerConnectTLSWebSocketWithHostOverwrittenInContextMissing(t *testing.T) {
	csp := New(Config{
		Connect:   []string{Self},
		WebSocket: true,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "localhost:3000", nil)
	require.NoError(t, err)
	r.TLS = &tls.ConnectionState{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	require.Equal(t, " connect-src 'self' wss://localhost:3000;", header)
}

func TestHandlerConnectWebSocketOnly(t *testing.T) {
	csp := New(Config{
		WebSocket: true,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	require.Equal(t, " connect-src ws://localhost:3000;", header)
}

func TestHandlerImg(t *testing.T) {
	csp := New(Config{
		Img: []string{Self},
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	require.Equal(t, " img-src 'self';", header)
}

func TestHandlerStyle(t *testing.T) {
	csp := New(Config{
		Style: []string{Self},
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	require.Equal(t, " style-src 'self';", header)
}

func TestHandlerEverything(t *testing.T) {
	csp := New(Config{
		Default: []string{None},
		Script:  []string{Self},
		Connect: []string{Self},
		Img:     []string{Self},
		Style:   []string{Self},
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	require.Equal(t, "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';", header)
}

func TestHandlerMultiValues(t *testing.T) {
	csp := New(Config{
		Default: []string{None, "default-test"},
		Script:  []string{Self, "script-test"},
		Connect: []string{Self, "connect-test"},
		Img:     []string{Self, "img-test"},
		Style:   []string{Self, "style-test"},
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	require.Equal(t, "default-src 'none' default-test; script-src 'self' script-test; connect-src 'self' connect-test; img-src 'self' img-test; style-src 'self' style-test;", header)
}

func TestHandlerAny(t *testing.T) {
	csp := New(Config{
		Default: []string{Any},
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	require.Equal(t, "default-src *;", header)
}

func TestNegroniIntegration(t *testing.T) {
	csp := New(Config{
		Default: []string{None},
		Script:  []string{Self},
		Connect: []string{Self},
		Img:     []string{Self},
		Style:   []string{Self},
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello World")
	})
	n := negroni.Classic()
	n.UseFunc(csp.NegroniHandlerFunc())
	n.UseHandler(mux)
	ts := httptest.NewServer(n)
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fail()
	}
	_, err = ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fail()
	}

	expected := "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';"
	policy := res.Header.Get(CSPHeader)
	require.Equal(t, expected, policy)
}

// Ensure Middleware Chain is being invoked
func TestHandlerNegroniMiddlewareChain(t *testing.T) {
	csp := New(Config{
		Connect: []string{Self},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello World")
	})
	n := negroni.Classic()
	n.UseFunc(csp.NegroniHandlerFunc())
	n.Use(xrequestid.New(16))
	n.UseHandler(mux)
	ts := httptest.NewServer(n)
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fail()
	}
	_, err = ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fail()
	}
	cspHeader := res.Header.Get(CSPHeader)
	xRequestID := res.Header.Get("X-Request-Id")
	require.Equal(t, "connect-src 'self';", cspHeader)
	require.NotEqual(t, "", xRequestID)
}

func TestAliceIntegration(t *testing.T) {
	csp := New(Config{
		Default: []string{None},
		Script:  []string{Self},
		Connect: []string{Self},
		Img:     []string{Self},
		Style:   []string{Self},
		Font:    []string{Self},
	})
	stdChain := alice.New(csp.Middleware)
	mux := http.NewServeMux()
	mux.Handle("/", stdChain.ThenFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello World")
	}))
	n := negroni.Classic()
	n.UseHandler(mux)
	ts := httptest.NewServer(n)
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fail()
	}
	_, err = ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fail()
	}
	require.Equal(t, "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; font-src 'self';", res.Header.Get(CSPHeader))
}

func TestPartialConfig(t *testing.T) {
	csp := New(Config{
		Script:  []string{Self},
		Connect: []string{Self},
	})
	stdChain := alice.New(csp.Middleware)
	mux := http.NewServeMux()
	mux.Handle("/", stdChain.ThenFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello World")
	}))
	n := negroni.Classic()
	n.UseHandler(mux)
	ts := httptest.NewServer(n)
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fail()
	}
	_, err = ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fail()
	}

	require.Equal(t, "script-src 'self'; connect-src 'self';", res.Header.Get(CSPHeader))
}

func TestHandlerReportURI(t *testing.T) {
	reportURI := "https://example.com/csp-reports"
	csp := New(Config{
		ReportURI: reportURI,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	fn(rw, r)

	require.Equal(t, fmt.Sprintf(" report-uri %s;", reportURI), rw.Header().Get(CSPHeader))
}
