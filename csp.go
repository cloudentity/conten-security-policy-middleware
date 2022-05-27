package csp

import (
	"fmt"
	"github.com/urfave/negroni"
	"net/http"
	"strings"
)

// Helpful constants for CSP values
const (
	Self       = "'self'"
	None       = "'none'"
	Any        = "*"
	CSPHeader  = "Content-Security-Policy"
	DefaultSrc = "default-src"
	ScriptSrc  = "script-src"
	ConnectSrc = "connect-src"
	ImgSrc     = "img-src"
	FontSrc    = "font-src"
	StyleSrc   = "style-src"
	ReportURI  = "report-uri"
)

// Config is Content Security Policy Configuration. If you do not define a
// policy string it will not be included in the policy output
type Config struct {
	WebSocket      bool     // enable dynamic websocket support in CSP
	HostContextKey string   // key in Context storing the original HTTP Host
	Default        []string // default-src CSP policy
	Script         []string // script-src CSP policy
	Connect        []string // connect-src CSP policy
	Img            []string // img-src CSP policy
	Style          []string // style-src CSP policy
	Font           []string // font-src CSP policy
	ReportURI      string   // report-uri CSP violation reports URI
	IgnorePrefix   []string // URL prefixes not to apply CSP too
}

// StarterConfig is a reasonable default set of policies.
//
// Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style: 'self';
func StarterConfig() Config {
	return Config{
		Default: []string{None},
		Script:  []string{Self},
		Connect: []string{Self},
		Img:     []string{Self},
		Style:   []string{Self},
	}
}

// CSP is a http middleware that configures CSP in the response header of an http request
type CSP struct {
	*Config
	handler http.HandlerFunc
}

// New returns a new instance of CSP Middleware
func New(config Config) *CSP {
	instance := &CSP{Config: &config}
	instance.handler = instance.handlerFunc()
	return instance
}

// NegroniHandlerFunc returns a function with the negroni middleware interface
func (csp *CSP) NegroniHandlerFunc() negroni.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		csp.handler(rw, r)
		if next != nil {
			next(rw, r)
		}
	}
}

// Middleware returns a function with the http.Handler interface and provides
// github.com/justinas/alice integration
func (csp *CSP) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		csp.handler(rw, r)
		if next != nil {
			next.ServeHTTP(rw, r)
		}
	})
}

// HandlerFunc returns a function the http.HandlerFunc interface
func (csp *CSP) HandlerFunc() http.HandlerFunc {
	return csp.handler
}

// handlerFunc is the http.HandlerFunc interface
func (csp *CSP) handlerFunc() http.HandlerFunc {
	// Do as much work during construction as possible
	var defaultPolicy, scriptPolicy, connectPolicy, imgPolicy, stylePolicy, fontPolicy, reportPolicy, baseConnectPolicy string
	if len(csp.Default) > 0 {
		defaultPolicy = fmt.Sprintf("%s %s;", DefaultSrc, strings.Join(csp.Default, " "))
	}
	if len(csp.Script) > 0 {
		scriptPolicy = fmt.Sprintf(" %s %s;", ScriptSrc, strings.Join(csp.Script, " "))
	}
	if len(csp.Connect) > 0 {
		baseConnectPolicy = fmt.Sprintf(" %s %s", ConnectSrc, strings.Join(csp.Connect, " "))
	}
	if len(csp.Img) > 0 {
		imgPolicy = fmt.Sprintf(" %s %s;", ImgSrc, strings.Join(csp.Img, " "))
	}
	if len(csp.Style) > 0 {
		stylePolicy = fmt.Sprintf(" %s %s;", StyleSrc, strings.Join(csp.Style, " "))
	}
	if len(csp.Font) > 0 {
		fontPolicy = fmt.Sprintf(" %s %s;", FontSrc, strings.Join(csp.Font, " "))
	}
	if csp.ReportURI != "" {
		reportPolicy = fmt.Sprintf(" %s %s;", ReportURI, csp.ReportURI)
	}
	if csp.WebSocket && len(csp.Connect) == 0 {
		baseConnectPolicy = " " + ConnectSrc
	}
	preConnectPolicy := defaultPolicy + scriptPolicy
	postConnectPolicy := imgPolicy + stylePolicy + fontPolicy + reportPolicy
	return func(rw http.ResponseWriter, r *http.Request) {
		for _, prefix := range csp.IgnorePrefix {
			// exclude specified paths from CSP protection
			if strings.HasPrefix(r.URL.Path, prefix) {
				return
			}
		}
		connectPolicy = baseConnectPolicy
		if csp.WebSocket {
			host := r.Host

			if csp.HostContextKey != "" {
				if hostOverwrite, ok := r.Context().Value(csp.HostContextKey).(string); ok && hostOverwrite != "" {
					host = hostOverwrite
				}
			}

			proto := "ws"
			if r.TLS != nil {
				proto = "wss"
			}
			connectPolicy = fmt.Sprintf("%s %s://%s", connectPolicy, proto, host)
		}
		if len(connectPolicy) > 0 {
			connectPolicy += ";"
		}
		policy := fmt.Sprintf("%s%s%s", preConnectPolicy, connectPolicy, postConnectPolicy)
		if policy != "" {
			rw.Header().Add(CSPHeader, policy)
		}
	}
}
