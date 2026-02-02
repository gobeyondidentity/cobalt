package mockhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Handler is a function that handles an HTTP request and returns true if it handled it.
type Handler func(w http.ResponseWriter, r *http.Request) bool

// ServerBuilder builds mock HTTP servers with configurable behavior.
type ServerBuilder struct {
	handlers    []Handler
	useTLS      bool
	defaultCode int
	capture     *Capture
}

// New creates a new ServerBuilder.
func New() *ServerBuilder {
	return &ServerBuilder{
		defaultCode: http.StatusNotFound,
	}
}

// TLS enables TLS for the mock server.
func (b *ServerBuilder) TLS() *ServerBuilder {
	b.useTLS = true
	return b
}

// DefaultStatus sets the status code returned when no handler matches.
func (b *ServerBuilder) DefaultStatus(code int) *ServerBuilder {
	b.defaultCode = code
	return b
}

// Handler adds a custom handler function.
func (b *ServerBuilder) Handler(h Handler) *ServerBuilder {
	b.handlers = append(b.handlers, h)
	return b
}

// JSON returns a JSON response for requests matching the given path.
// Uses HTTP 200 status code.
func (b *ServerBuilder) JSON(path string, response any) *ServerBuilder {
	return b.JSONWithStatus(path, http.StatusOK, response)
}

// JSONWithStatus returns a JSON response with a specific status code.
func (b *ServerBuilder) JSONWithStatus(path string, code int, response any) *ServerBuilder {
	return b.Handler(func(w http.ResponseWriter, r *http.Request) bool {
		if !matchPath(r.URL.Path, path) {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(response)
		return true
	})
}

// Status returns an empty response with the given status code.
func (b *ServerBuilder) Status(path string, code int) *ServerBuilder {
	return b.Handler(func(w http.ResponseWriter, r *http.Request) bool {
		if !matchPath(r.URL.Path, path) {
			return false
		}
		w.WriteHeader(code)
		return true
	})
}

// StatusWithBody returns a response with the given status code and body.
func (b *ServerBuilder) StatusWithBody(path string, code int, body string) *ServerBuilder {
	return b.Handler(func(w http.ResponseWriter, r *http.Request) bool {
		if !matchPath(r.URL.Path, path) {
			return false
		}
		w.WriteHeader(code)
		w.Write([]byte(body))
		return true
	})
}

// Text returns a plain text response.
func (b *ServerBuilder) Text(path string, text string) *ServerBuilder {
	return b.TextWithStatus(path, http.StatusOK, text)
}

// TextWithStatus returns a plain text response with a specific status code.
func (b *ServerBuilder) TextWithStatus(path string, code int, text string) *ServerBuilder {
	return b.Handler(func(w http.ResponseWriter, r *http.Request) bool {
		if !matchPath(r.URL.Path, path) {
			return false
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(code)
		w.Write([]byte(text))
		return true
	})
}

// Delay adds a delay before processing requests to a path.
// Useful for testing timeouts.
func (b *ServerBuilder) Delay(path string, delay func()) *ServerBuilder {
	return b.Handler(func(w http.ResponseWriter, r *http.Request) bool {
		if !matchPath(r.URL.Path, path) {
			return false
		}
		delay()
		return false // Continue to next handler
	})
}

// RequireBasicAuth enforces Basic authentication for all requests.
// Returns 401 if credentials don't match.
func (b *ServerBuilder) RequireBasicAuth(username, password string) *ServerBuilder {
	return b.Handler(func(w http.ResponseWriter, r *http.Request) bool {
		user, pass, ok := r.BasicAuth()
		if !ok || user != username || pass != password {
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}
		return false // Continue to next handler
	})
}

// RequireHeader ensures a specific header is present with an expected value.
// Returns 400 if header is missing or doesn't match.
func (b *ServerBuilder) RequireHeader(name, value string) *ServerBuilder {
	return b.Handler(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get(name) != value {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		return false
	})
}

// RequireHeaderPresent ensures a specific header is present (any value).
// Returns 400 if header is missing.
func (b *ServerBuilder) RequireHeaderPresent(name string) *ServerBuilder {
	return b.Handler(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get(name) == "" {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		return false
	})
}

// Capture enables request capture for inspection in tests.
// Returns the Capture object for accessing captured requests.
func (b *ServerBuilder) Capture() *Capture {
	if b.capture == nil {
		b.capture = &Capture{}
		b.Handler(func(w http.ResponseWriter, r *http.Request) bool {
			b.capture.record(r)
			return false // Continue to next handler
		})
	}
	return b.capture
}

// Route adds a handler that matches both method and path.
func (b *ServerBuilder) Route(method, path string, handler http.HandlerFunc) *ServerBuilder {
	return b.Handler(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != method || !matchPath(r.URL.Path, path) {
			return false
		}
		handler(w, r)
		return true
	})
}

// RouteFunc adds a handler that matches path with a custom response function.
func (b *ServerBuilder) RouteFunc(path string, handler http.HandlerFunc) *ServerBuilder {
	return b.Handler(func(w http.ResponseWriter, r *http.Request) bool {
		if !matchPath(r.URL.Path, path) {
			return false
		}
		handler(w, r)
		return true
	})
}

// Build creates the httptest.Server with all configured handlers.
// Returns the server and the HTTP client to use (important for TLS servers).
func (b *ServerBuilder) Build() (*httptest.Server, *http.Client) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range b.handlers {
			if h(w, r) {
				return
			}
		}
		// No handler matched
		w.WriteHeader(b.defaultCode)
	})

	var server *httptest.Server
	if b.useTLS {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}

	return server, server.Client()
}

// BuildURL creates the server and returns the URL (convenience for non-TLS).
func (b *ServerBuilder) BuildURL() (string, func()) {
	server, _ := b.Build()
	return server.URL, server.Close
}

// matchPath checks if the request path matches the pattern.
// Supports exact match and prefix match with "*" suffix.
func matchPath(requestPath, pattern string) bool {
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(requestPath, prefix)
	}
	return requestPath == pattern
}

// Capture stores captured HTTP requests for test assertions.
type Capture struct {
	mu       sync.Mutex
	requests []CapturedRequest
}

// CapturedRequest holds data from a captured HTTP request.
type CapturedRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Body    []byte
	Query   map[string][]string
}

func (c *Capture) record(r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var body []byte
	if r.Body != nil {
		body, _ = readAndRestore(r)
	}

	c.requests = append(c.requests, CapturedRequest{
		Method:  r.Method,
		Path:    r.URL.Path,
		Headers: r.Header.Clone(),
		Body:    body,
		Query:   r.URL.Query(),
	})
}

// Count returns the number of captured requests.
func (c *Capture) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

// Last returns the most recent captured request, or nil if none.
func (c *Capture) Last() *CapturedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.requests) == 0 {
		return nil
	}
	return &c.requests[len(c.requests)-1]
}

// All returns all captured requests.
func (c *Capture) All() []CapturedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]CapturedRequest, len(c.requests))
	copy(result, c.requests)
	return result
}

// Get returns the request at index i, or nil if out of bounds.
func (c *Capture) Get(i int) *CapturedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i < 0 || i >= len(c.requests) {
		return nil
	}
	return &c.requests[i]
}

// Clear removes all captured requests.
func (c *Capture) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = nil
}

// BodyJSON decodes the request body as JSON into v.
func (r *CapturedRequest) BodyJSON(v any) error {
	return json.Unmarshal(r.Body, v)
}

// readAndRestore reads the body and restores it for later handlers.
func readAndRestore(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	// Read the body
	body := make([]byte, 0, 1024)
	buf := make([]byte, 512)
	for {
		n, err := r.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}
	r.Body.Close()

	// Restore the body
	r.Body = &readCloser{data: body}
	return body, nil
}

type readCloser struct {
	data []byte
	pos  int
}

func (rc *readCloser) Read(p []byte) (n int, err error) {
	if rc.pos >= len(rc.data) {
		return 0, http.ErrBodyReadAfterClose
	}
	n = copy(p, rc.data[rc.pos:])
	rc.pos += n
	return n, nil
}

func (rc *readCloser) Close() error {
	return nil
}
