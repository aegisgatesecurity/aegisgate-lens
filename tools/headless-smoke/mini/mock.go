// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens v0.1.4 - Headless Smoke Test: Per-Provider HTTPS Mock
//
// Self-signed HTTPS server on localhost that serves provider-specific
// mock HTML based on the Host header. The mini smoke navigates to
// https://localhost:PORT/ for every host but sets a different Host
// header (chatgpt.com, claude.ai, gemini.google.com, etc.) so the
// mock serves the right per-provider DOM shape.
//
// The mock HTML files are in test/headless-smoke/mock/platform-testdata/
// (the 9 active provider mocks: chatgpt, claude, gemini, copilot,
// perplexity, duck, grok, mistral, plus legacy chat-openai).
//
// The mock pages set window.__lensMockHost to the corresponding host
// so src/util/selectors.js's identifyProvider() returns the right
// provider config. This is test-only: in production, no real AI
// page sets window.__lensMockHost.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MOCK_DIR is the directory containing the 9 per-provider mock HTML files.
// Per the F-7 e2e tests, this directory must contain: chatgpt.html,
// chat-openai.html, claude.html, gemini.html, copilot.html, perplexity.html,
// duck.html, grok.html, mistral.html. The x.html is legacy (Grok on X).
const MOCK_DIR = "test/headless-smoke/mock/platform-testdata/"

// providerMap: Host header -> mock file name.
// Hosts are matched case-insensitively. The first match wins.
// Each entry corresponds to a PROVIDER in src/util/selectors.js.
var providerMap = map[string]string{
	"chat.openai.com":          "chat-openai.html", // legacy ChatGPT (old host)
	"chatgpt.com":              "chatgpt.html",     // current ChatGPT
	"claude.ai":                "claude.html",      // ProseMirror contenteditable
	"gemini.google.com":        "gemini.html",      // ql-editor contenteditable
	"copilot.microsoft.com":    "copilot.html",     // userInput
	"copilot.cloud.microsoft":  "copilot.html",     // same DOM, alternative host
	"perplexity.ai":            "perplexity.html",  // user-input textarea
	"www.perplexity.ai":        "perplexity.html",  // www variant
	"duck.ai":                  "duck.html",        // Duck.ai
	"grok.com":                 "grok.html",        // Grok
	"www.grok.com":             "grok.html",        // www variant
	"chat.mistral.ai":          "mistral.html",     // prompt-textarea
	"le-chat.mistral.ai":       "mistral.html",     // same DOM
	"x.com":                    "x.html",           // legacy Grok on X
}

// loadMocks reads all mock HTML files at startup. Missing files are
// skipped (the smoke will fail later in the test when the smoke
// binary tries to load the missing provider, which is the right
// failure mode for CI).
func loadMocks() (map[string]string, error) {
	mocks := make(map[string]string)
	// First, find the absolute path of the mocks dir
	absMockDir := MOCK_DIR
	if !filepath.IsAbs(absMockDir) {
		// Resolve relative to current working directory
		if abs, err := filepath.Abs(absMockDir); err == nil {
			absMockDir = abs
		}
	}
	// Walk the providerMap and load each file
	for host, file := range providerMap {
		path := filepath.Join(absMockDir, file)
		content, err := os.ReadFile(path)
		if err != nil {
			// Skip missing files (e.g., x.html may not exist in CI)
			fmt.Fprintf(os.Stderr, "mock: skipping %s (%v)\n", path, err)
			continue
		}
		mocks[host] = string(content)
	}
	return mocks, nil
}

type mockServer struct {
	port   int
	mocks  map[string]string
	server *http.Server
	ln     net.Listener
}

func newMockServer(port int, mocks map[string]string) *mockServer {
	return &mockServer{port: port, mocks: mocks}
}

func (m *mockServer) start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		// Route by Host header (case-insensitive). Fall back to
		// chatgpt.html for unknown hosts (e.g., "localhost:8443"
		// without an explicit Host header).
		host := strings.ToLower(r.Host)
		// Strip the port from the host (e.g., "chatgpt.com:8443" -> "chatgpt.com")
		if idx := strings.Index(host, ":"); idx >= 0 {
			host = host[:idx]
		}
		content, ok := m.mocks[host]
		if !ok {
			// Fall back to chatgpt.html
			content = m.mocks["chatgpt.com"]
		}
		_, _ = w.Write([]byte(content))
	})

	// Generate self-signed cert for localhost
	_, tlsConfig, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("generate cert: %w", err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", m.port))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	m.ln = ln
	m.server = &http.Server{
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	// Start serving in background
	go func() {
		_ = m.server.ServeTLS(ln, "", "")
	}()

	time.Sleep(100 * time.Millisecond)
	return nil
}

func (m *mockServer) stop() {
	if m.server != nil {
		_ = m.server.Close()
	}
}

// generateSelfSignedCert creates a self-signed cert for localhost.
// Returns the PEM cert bytes and a TLS config that uses it.
func generateSelfSignedCert() ([]byte, *tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"AegisGate Lens Smoke Test"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	return certPEM, tlsConfig, nil
}
