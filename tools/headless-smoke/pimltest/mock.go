
// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens v0.1.0-beta - Headless Smoke Test: HTTPS mock server

// Self-signed HTTPS server on localhost. Serves a page that mimics
// the chat.openai.com DOM structure (id="prompt-textarea",
// data-testid="send-button") so the Lens content_scripts match pattern
// fires and the prompt-detect selector works.
//
// We use crypto/tls to generate a self-signed cert at startup.
// Chromium 149 accepts self-signed certs on localhost as a secure context.
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
	"os"
	"path/filepath"
	"net/http"
	"strings"
	"time"
)

const mockHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Mock ChatGPT (AegisGate Lens smoke test)</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
  #prompt-textarea { width: 100%; min-height: 120px; padding: 12px; border: 1px solid #ccc; border-radius: 8px; font-size: 14px; font-family: inherit; }
  button[data-testid="send-button"] { margin-top: 12px; padding: 8px 16px; background: #10a37f; color: white; border: none; border-radius: 4px; cursor: pointer; }
  .test-info { background: #f0f0f0; padding: 12px; border-radius: 8px; margin-bottom: 16px; font-size: 13px; }
</style>
</head>
<body>
<div class="test-info">
  <strong>AegisGate Lens smoke test mock</strong>
  <p>This is a local test page that mimics the chat.openai.com DOM structure.
  The Lens content script should attach to the textarea below and warn when
  sensitive data is detected.</p>
  <p>Hostname: <code id="hostname"></code></p>
  <p id="lens-status">Lens status: <span id="lens-state">checking...</span></p>
</div>
<textarea id="prompt-textarea" placeholder="Message ChatGPT..." autofocus></textarea>
<br>
<button data-testid="send-button">Send</button>
<script>
  document.getElementById('hostname').textContent = window.location.hostname;
  // Check if Lens is loaded
  setTimeout(() => {
    const s = document.getElementById('lens-state');
    if (window.__lens_cs) {
      s.textContent = 'LOADED (window.__lens_cs is set)';
      s.style.color = 'green';
    } else {
      s.textContent = 'NOT LOADED (window.__lens_cs is undefined)';
      s.style.color = 'red';
    }
  }, 1000);
</script>
</body>
</html>`

type mockServer struct {
	port   int
	server *http.Server
	ln     net.Listener
}

func newMockServer(port int) *mockServer {
	return &mockServer{port: port}
}

func (m *mockServer) start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockHTML))
	})
	// Serve the model files from the dist directory
	mux.HandleFunc("/detectors/ml/", func(w http.ResponseWriter, r *http.Request) {
		mlDir := os.Getenv("LENS_ML_DIR")
		if mlDir == "" {
			http.Error(w, "LENS_ML_DIR env var not set", 500)
			return
		}
		// r.URL.Path is /detectors/ml/FILENAME
		// LENS_ML_DIR already ends in /detectors/ml, so strip the prefix
		name := strings.TrimPrefix(r.URL.Path, "/detectors/ml/")
		full := filepath.Join(mlDir, name)
		http.ServeFile(w, r, full)
	})
	// Serve the onnxruntime-web files (ort-wasm.wasm etc.) from the dist
	mux.HandleFunc("/vendor/onnxruntime-web/", func(w http.ResponseWriter, r *http.Request) {
		// r.URL.Path is like /vendor/onnxruntime-web/ort-wasm.wasm
		// We need the dist dir, which we get from the LENS_DIST env var
		distDir := os.Getenv("LENS_DIST")
		if distDir == "" {
			http.Error(w, "LENS_DIST env var not set", 500)
			return
		}
		rel := r.URL.Path[len("/"):]  // vendor/onnxruntime-web/ort-wasm.wasm
		full := filepath.Join(distDir, rel)
		http.ServeFile(w, r, full)
	})

	// Generate self-signed cert for localhost
	cert, tlsConfig, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("generate cert: %w", err)
	}
	_ = cert

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
		// We need to use ServeTLS but the cert is in TLSConfig
		// Use the listener directly
		_ = m.server.ServeTLS(ln, "", "")
	}()

	// Give it a moment to start
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
	// Generate ECDSA private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
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

	// Self-sign
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// Encode cert to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	// Encode private key to PEM
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	// Parse back into tls.Certificate
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

// trim is unused but kept for future expansion
func trim(s string) string {
	return strings.TrimSpace(s)
}
