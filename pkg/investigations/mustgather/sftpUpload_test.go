package mustgather

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/utils"
)

// errorReader simulates read errors
type errorReader struct {
	data      []byte
	readCount int
	errorAt   int // error after this many reads
	err       error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	r.readCount++
	if r.errorAt > 0 && r.readCount > r.errorAt {
		return 0, r.err
	}

	if len(r.data) == 0 {
		return 0, io.EOF
	}

	n = copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// errorWriter simulates write errors
type errorWriter struct {
	buf     bytes.Buffer
	errorAt int // error after this many bytes
	shortAt int // short write after this many bytes (write fewer bytes than requested)
	err     error
}

func (w *errorWriter) Write(p []byte) (n int, err error) {
	currentSize := w.buf.Len()

	if w.errorAt > 0 && currentSize >= w.errorAt {
		return 0, w.err
	}

	if w.shortAt > 0 && currentSize >= w.shortAt {
		// Simulate short write - write only half the bytes
		n = len(p) / 2
		if n == 0 && len(p) > 0 {
			n = 1
		}
		w.buf.Write(p[:n])
		return n, nil
	}

	return w.buf.Write(p)
}

func TestCopyWithContext(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		setupCtx    func() (context.Context, context.CancelFunc)
		setupWriter func() io.Writer
		setupReader func(data []byte) io.Reader
		wantErr     bool
		wantErrType error
		wantBytes   int64
		description string
	}{
		{
			name:  "successful copy small data",
			input: "Hello, World!",
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			setupWriter: func() io.Writer {
				return &bytes.Buffer{}
			},
			setupReader: func(data []byte) io.Reader {
				return bytes.NewReader(data)
			},
			wantErr:     false,
			wantBytes:   13,
			description: "Should successfully copy small data",
		},
		{
			name:  "successful copy large data multiple chunks",
			input: strings.Repeat("A", 1000*1024), // 1000KB - requires multiple 128KB chunks
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			setupWriter: func() io.Writer {
				return &bytes.Buffer{}
			},
			setupReader: func(data []byte) io.Reader {
				return bytes.NewReader(data)
			},
			wantErr:     false,
			wantBytes:   1000 * 1024,
			description: "Should successfully copy large data across multiple chunks",
		},
		{
			name:  "context cancelled before copy",
			input: "test data",
			setupCtx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // Cancel immediately
				return ctx, cancel
			},
			setupWriter: func() io.Writer {
				return &bytes.Buffer{}
			},
			setupReader: func(data []byte) io.Reader {
				return bytes.NewReader(data)
			},
			wantErr:     true,
			wantErrType: context.Canceled,
			wantBytes:   0,
			description: "Should return immediately if context already cancelled",
		},
		{
			name:  "read error during copy",
			input: "some data",
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			setupWriter: func() io.Writer {
				return &bytes.Buffer{}
			},
			setupReader: func(data []byte) io.Reader {
				return &errorReader{
					data:    data,
					errorAt: 1, // Error after first read
					err:     errors.New("read error"),
				}
			},
			wantErr:     true,
			description: "Should return error when read fails",
		},
		{
			name:  "write error during copy",
			input: strings.Repeat("D", 256*1024), // 256KB to span multiple chunks
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			setupWriter: func() io.Writer {
				return &errorWriter{
					errorAt: 128 * 1024, // Error exactly after first chunk (128KB)
					err:     errors.New("write error"),
				}
			},
			setupReader: func(data []byte) io.Reader {
				return bytes.NewReader(data)
			},
			wantErr:     true,
			description: "Should return error when write fails",
		},
		{
			name:  "short write error",
			input: strings.Repeat("C", 256*1024), // 256KB to ensure short write is detected
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			setupWriter: func() io.Writer {
				return &errorWriter{
					shortAt: 128 * 1024, // Short write after 128KB
				}
			},
			setupReader: func(data []byte) io.Reader {
				return bytes.NewReader(data)
			},
			wantErr:     true,
			wantErrType: io.ErrShortWrite,
			description: "Should return ErrShortWrite when writer doesn't accept all bytes",
		},
		{
			name:  "empty data",
			input: "",
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			setupWriter: func() io.Writer {
				return &bytes.Buffer{}
			},
			setupReader: func(data []byte) io.Reader {
				return bytes.NewReader(data)
			},
			wantErr:     false,
			wantBytes:   0,
			description: "Should handle empty data gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := tt.setupCtx()
			defer cancel()

			data := []byte(tt.input)
			reader := tt.setupReader(data)
			writer := tt.setupWriter()

			// If writer is a buffer, we can verify the content
			var buf *bytes.Buffer
			if b, ok := writer.(*bytes.Buffer); ok {
				buf = b
			}

			n, err := copyWithContext(ctx, writer, reader)

			// Check error expectations
			if tt.wantErr {
				if err == nil {
					t.Errorf("%s: expected error but got none", tt.description)
				}
				if tt.wantErrType != nil && !errors.Is(err, tt.wantErrType) {
					t.Errorf("%s: expected error type %v, got %v", tt.description, tt.wantErrType, err)
				}
			} else if err != nil {
				t.Errorf("%s: unexpected error: %v", tt.description, err)
			}

			// Check bytes written (if we have a specific expectation)
			if tt.wantBytes > 0 && n != tt.wantBytes {
				t.Errorf("%s: expected %d bytes written, got %d", tt.description, tt.wantBytes, n)
			}

			// Verify content if we successfully copied to a buffer
			if !tt.wantErr && buf != nil {
				if buf.String() != tt.input {
					t.Errorf("%s: content mismatch. Expected %q, got %q", tt.description, tt.input, buf.String())
				}
			}
		})
	}
}

func TestGetAnonymousSftpCredentials(t *testing.T) {
	tests := []struct {
		name            string
		setupServer     func() string // Returns server URL
		setupCtx        func() (context.Context, context.CancelFunc)
		wantUsername    string
		wantToken       string
		wantErr         bool
		wantErrContains string
		description     string
	}{
		{
			name: "successful credential fetch",
			setupServer: func() string {
				return createMockServer(t, http.StatusOK, `{
					"username": "test-user-12345",
					"token": "test-token-abcdef",
					"expiryDate": "2024-12-31T23:59:59Z"
				}`)
			},
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			wantUsername: "test-user-12345",
			wantToken:    "test-token-abcdef",
			wantErr:      false,
			description:  "Should successfully fetch credentials from valid server response",
		},
		{
			name: "HTTP 500 internal server error",
			setupServer: func() string {
				return createMockServer(t, http.StatusInternalServerError, `{"error": "internal server error"}`)
			},
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			wantErr:         true,
			wantErrContains: "SFTP credential request failed with status 500",
			description:     "Should return error for 500 status code",
		},
		{
			name: "HTTP 404 not found",
			setupServer: func() string {
				return createMockServer(t, http.StatusNotFound, `{"error": "endpoint not found"}`)
			},
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			wantErr:         true,
			wantErrContains: "SFTP credential request failed with status 404",
			description:     "Should return error for 404 status code",
		},
		{
			name: "HTTP 503 service unavailable",
			setupServer: func() string {
				return createMockServer(t, http.StatusServiceUnavailable, `{"error": "service temporarily unavailable"}`)
			},
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			wantErr:         true,
			wantErrContains: "SFTP credential request failed with status 503",
			description:     "Should return error for 503 status code",
		},
		{
			name: "invalid JSON response",
			setupServer: func() string {
				return createMockServer(t, http.StatusOK, `{invalid json}`)
			},
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			wantErr:     true,
			description: "Should return error for malformed JSON",
		},
		{
			name: "empty response body",
			setupServer: func() string {
				return createMockServer(t, http.StatusOK, ``)
			},
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			wantErr:     true,
			description: "Should return error for empty response",
		},
		{
			name: "missing username in response",
			setupServer: func() string {
				return createMockServer(t, http.StatusOK, `{
					"token": "test-token-abcdef",
					"expiryDate": "2024-12-31T23:59:59Z"
				}`)
			},
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			wantUsername: "",
			wantToken:    "test-token-abcdef",
			wantErr:      false,
			description:  "Should handle missing username field (returns empty string)",
		},
		{
			name: "missing token in response",
			setupServer: func() string {
				return createMockServer(t, http.StatusOK, `{
					"username": "test-user-12345",
					"expiryDate": "2024-12-31T23:59:59Z"
				}`)
			},
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			wantUsername: "test-user-12345",
			wantToken:    "",
			wantErr:      false,
			description:  "Should handle missing token field (returns empty string)",
		},
		{
			name: "context timeout",
			setupServer: func() string {
				return createSlowMockServer(t, 200*time.Millisecond, http.StatusOK, `{
					"username": "test-user",
					"token": "test-token"
				}`)
			},
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 10*time.Millisecond)
			},
			wantErr:     true,
			description: "Should return error when context times out",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock server
			serverURL := tt.setupServer()

			// Create a mock HTTP client that points to our test server
			mockClient := &mockHTTPClient{serverURL: serverURL}

			ctx, cancel := tt.setupCtx()
			defer cancel()

			username, token, err := getAnonymousSftpCredentials(ctx, mockClient)

			// Check error expectations
			if tt.wantErr {
				if err == nil {
					t.Errorf("%s: expected error but got none", tt.description)
				}
				if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("%s: expected error containing %q, got %q", tt.description, tt.wantErrContains, err.Error())
				}
			} else if err != nil {
				t.Errorf("%s: unexpected error: %v", tt.description, err)
			}

			// Check returned values
			if !tt.wantErr {
				if username != tt.wantUsername {
					t.Errorf("%s: expected username %q, got %q", tt.description, tt.wantUsername, username)
				}
				if token != tt.wantToken {
					t.Errorf("%s: expected token %q, got %q", tt.description, tt.wantToken, token)
				}
			}
		})
	}
}

// createMockServer creates a test HTTP server that returns a specific status and body
func createMockServer(t *testing.T, status int, body string) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and content type
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		// Verify request body contains isAnonymous: true
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed to read request body: %v", err)
		}
		if !strings.Contains(string(bodyBytes), `"isAnonymous":true`) {
			t.Errorf("Expected request body to contain isAnonymous:true, got: %s", string(bodyBytes))
		}

		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// createSlowMockServer creates a test HTTP server that delays before responding
func createSlowMockServer(t *testing.T, delay time.Duration, status int, body string) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// mockHTTPClient implements HTTPDoer and redirects all requests to a test server
type mockHTTPClient struct {
	serverURL string
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// Replace the request URL with our test server URL
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(m.serverURL, "http://")
	return http.DefaultClient.Do(req)
}

// createFlakySftpCredentialServer creates a mock server that fails for the first
// N requests and then succeeds, simulating transient failures.
func createFlakySftpCredentialServer(t *testing.T, failCount int) string {
	t.Helper()
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if int(count) <= failCount {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error": "service temporarily unavailable"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"username": "retry-user",
			"token": "retry-token",
			"expiryDate": "2024-12-31T23:59:59Z"
		}`))
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestGetAnonymousSftpCredentials_RetryOnTransientFailure(t *testing.T) {
	tests := []struct {
		name         string
		failCount    int
		maxAttempts  int
		wantUsername string
		wantToken    string
		wantErr      bool
		description  string
	}{
		{
			name:         "succeeds after 1 transient failure",
			failCount:    1,
			maxAttempts:  3,
			wantUsername: "retry-user",
			wantToken:    "retry-token",
			wantErr:      false,
			description:  "Should succeed on second attempt after first returns 503",
		},
		{
			name:         "succeeds after 2 transient failures",
			failCount:    2,
			maxAttempts:  3,
			wantUsername: "retry-user",
			wantToken:    "retry-token",
			wantErr:      false,
			description:  "Should succeed on third attempt after two 503 errors",
		},
		{
			name:        "fails when all attempts exhausted",
			failCount:   5,
			maxAttempts: 3,
			wantErr:     true,
			description: "Should fail after all retry attempts are exhausted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverURL := createFlakySftpCredentialServer(t, tt.failCount)
			mockClient := &mockHTTPClient{serverURL: serverURL}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			var username, token string
			err := utils.WithRetriesContext(ctx, tt.maxAttempts, 10*time.Millisecond, func() error {
				attemptCtx, attemptCancel := context.WithTimeout(ctx, 5*time.Second)
				defer attemptCancel()
				var credErr error
				username, token, credErr = getAnonymousSftpCredentials(attemptCtx, mockClient)
				return credErr
			})

			if tt.wantErr {
				if err == nil {
					t.Errorf("%s: expected error but got none", tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("%s: unexpected error: %v", tt.description, err)
				}
				if username != tt.wantUsername {
					t.Errorf("%s: expected username %q, got %q", tt.description, tt.wantUsername, username)
				}
				if token != tt.wantToken {
					t.Errorf("%s: expected token %q, got %q", tt.description, tt.wantToken, token)
				}
			}
		})
	}
}

func TestGetAnonymousSftpCredentials_RetryRespectsContextCancellation(t *testing.T) {
	// Create a server that always fails
	serverURL := createFlakySftpCredentialServer(t, 100)
	mockClient := &mockHTTPClient{serverURL: serverURL}

	// Use a short timeout that will expire during backoff
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var username, token string
	err := utils.WithRetriesContext(ctx, 5, 1*time.Second, func() error {
		attemptCtx, attemptCancel := context.WithTimeout(ctx, 5*time.Second)
		defer attemptCancel()
		var credErr error
		username, token, credErr = getAnonymousSftpCredentials(attemptCtx, mockClient)
		return credErr
	})

	if err == nil {
		t.Fatal("expected error due to context cancellation, got nil")
	}
	if username != "" || token != "" {
		t.Errorf("expected empty credentials on failure, got username=%q token=%q", username, token)
	}
}
