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

func TestCspBase(t *testing.T) {

	var testcases = []struct {
		name           string
		csp            *CSP
		hostHeader     string
		tls            bool
		expectedHeader string
		ctx            context.Context
	}{
		{
			name:           "empty config",
			csp:            New(Config{}),
			expectedHeader: "",
		},
		{
			name: "default policy",
			csp: New(Config{
				Default: []string{None},
			}),
			expectedHeader: "default-src 'none';",
		},
		{
			name: "script policy",
			csp: New(Config{
				Script: []string{Self},
			}),
			expectedHeader: " script-src 'self';",
		},
		{
			name: "connect policy",
			csp: New(Config{
				Connect: []string{Self},
			}),
			expectedHeader: " connect-src 'self';",
		},
		{
			name: "img policy",
			csp: New(Config{
				Img: []string{Self},
			}),
			expectedHeader: " img-src 'self';",
		},
		{
			name: "style policy",
			csp: New(Config{
				Style: []string{Self},
			}),
			expectedHeader: " style-src 'self';",
		},
		{
			name: "everything",
			csp: New(Config{
				Default: []string{None},
				Script:  []string{Self},
				Connect: []string{Self},
				Img:     []string{Self},
				Style:   []string{Self},
			}),
			expectedHeader: "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';",
		},
		{
			name: "multi-values",
			csp: New(Config{
				Default: []string{None, "default-test"},
				Script:  []string{Self, "script-test"},
				Connect: []string{Self, "connect-test"},
				Img:     []string{Self, "img-test"},
				Style:   []string{Self, "style-test"},
			}),
			expectedHeader: "default-src 'none' default-test; script-src 'self' script-test; connect-src 'self' connect-test; img-src 'self' img-test; style-src 'self' style-test;",
		},
		{
			name: "any",
			csp: New(Config{
				Default: []string{Any},
			}),
			expectedHeader: "default-src *;",
		},

		{
			name: "websocket only",
			csp: New(Config{
				WebSocket: true,
			}),
			hostHeader:     "localhost:3000",
			expectedHeader: " connect-src ws://localhost:3000;",
		},
		{
			name: "connect websocket handler",
			csp: New(Config{
				Connect:   []string{Self},
				WebSocket: true,
			}),
			hostHeader:     "localhost:3000",
			expectedHeader: " connect-src 'self' ws://localhost:3000;",
		},
		{
			name: "connect tls websocket handler",
			csp: New(Config{
				Connect:   []string{Self},
				WebSocket: true,
			}),
			hostHeader:     "localhost:3000",
			tls:            true,
			expectedHeader: " connect-src 'self' wss://localhost:3000;",
		},
		{
			name: "connect tls websocket handler with host overwrite",
			csp: New(Config{
				Connect:   []string{Self},
				WebSocket: true,
			}).WithHostProvider(func(ctx context.Context) string {
				return ctx.Value("originalHost").(string)
			}),
			hostHeader:     "localhost:3000",
			tls:            true,
			expectedHeader: " connect-src 'self' wss://example.com;",
			ctx:            context.WithValue(context.Background(), "originalHost", "example.com"),
		},
		{
			name: "connect tls websocket handler with host empty in context",
			csp: New(Config{
				Connect:   []string{Self},
				WebSocket: true,
			}).WithHostProvider(func(ctx context.Context) string {
				return ctx.Value(123456).(string)
			}),
			hostHeader:     "localhost:3000",
			tls:            true,
			expectedHeader: " connect-src 'self' wss://localhost:3000;",
			ctx:            context.WithValue(context.Background(), 123456, ""),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			var (
				err error
				r   *http.Request
			)
			rw := httptest.NewRecorder()

			if tc.ctx != nil {
				r, err = http.NewRequestWithContext(tc.ctx, http.MethodGet, "localhost:3000", nil)
				require.NoError(tt, err)
			} else {
				r, err = http.NewRequestWithContext(context.Background(), http.MethodGet, "localhost:3000", nil)
				require.NoError(tt, err)
			}
			if tc.hostHeader != "" {
				r.Host = tc.hostHeader
			}
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			fn := tc.csp.HandlerFunc()
			fn(rw, r)
			header := rw.Header().Get(CSPHeader)
			require.Equal(t, tc.expectedHeader, header)

		})
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
