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
	if header != "default-src 'none';" {
		t.Log(header)
		t.Error("expected header to be default-src 'none'")
	}
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
	if header != " script-src 'self';" {
		t.Log(header)
		t.Error("expected script-src to be 'self'")
	}
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
	if header != " connect-src 'self';" {
		t.Log(header)
		t.Error("expected connect-src to be 'self'")
	}
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
	if header != " connect-src 'self' ws://localhost:3000;" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "'self' ws://localhost:3000;")
	}
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
	if header != " connect-src 'self' ws://localhost:3000;" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "'self' ws://localhost:3000;")
	}

	r = &http.Request{}
	r.Host = "localhost:3000"
	rw = httptest.NewRecorder()
	fn(rw, r)
	header = rw.Header().Get("Content-Security-Policy")
	if header != " connect-src 'self' ws://localhost:3000;" {
		t.Errorf("expected connect-src to be %q, got %q", "'self' ws://localhost:3000;", header)
	}
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
	if header != " connect-src 'self' wss://localhost:3000;" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "'self' wss://localhost:3000;")
	}
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
	if header != " connect-src 'self' wss://example.com;" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "'self' wss://example.com;")
	}
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
	if header != " connect-src 'self' wss://localhost:3000;" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "'self' wss://localhost:3000;")
	}
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
	if header != " connect-src 'self' wss://localhost:3000;" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "'self' wss://localhost:3000;")
	}
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
	if header != " connect-src ws://localhost:3000;" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "ws://localhost:3000;")
	}
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
	if header != " img-src 'self';" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "img-src 'self'")
	}
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
	if header != " style-src 'self';" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "style-src 'self'")
	}
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
	expected := "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';"
	if header != expected {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", expected)
	}
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
	expected := "default-src 'none' default-test; script-src 'self' script-test; connect-src 'self' connect-test; img-src 'self' img-test; style-src 'self' style-test;"
	if header != expected {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", expected)
	}
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
	expected := "default-src *;"
	if header != expected {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", expected)
	}
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
	if expected != policy {
		t.Errorf("Expected Policy %q, got %q", expected, policy)
	}
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
	if cspHeader != "connect-src 'self';" || xRequestID == "" {
		t.Log(cspHeader, xRequestID)
		t.Error("expected connect-src to be 'self' + random request id")
	}
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

	expected := "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; font-src 'self';"
	policy := res.Header.Get(CSPHeader)
	if expected != policy {
		t.Errorf("Expected Policy %q, got %q", expected, policy)
	}
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

	expected := "script-src 'self'; connect-src 'self';"
	policy := res.Header.Get(CSPHeader)
	if expected != policy {
		t.Errorf("Expected Policy %q, got %q", expected, policy)
	}
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
	header := rw.Header().Get(CSPHeader)
	if header != fmt.Sprintf(" report-uri %s;", reportURI) {
		t.Log(header)
		t.Errorf("expected report-uri to be %q", reportURI)
	}
}
