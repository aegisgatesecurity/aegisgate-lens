// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens v0.1.0-beta - Headless Smoke Test: Chromium spawn

// Spawn Chromium 149 with --load-extension, wait for CDP port to be ready.
package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type chromeProcess struct {
	cmd     *exec.Cmd
	dataDir string
	closed  bool
}

func spawnChromium(binary, distPath string, port int, timeout time.Duration) (*chromeProcess, error) {
	// Create a temporary user data dir.
	dataDir, err := os.MkdirTemp("", "lens-smoke-chrome-*")
	if err != nil {
		return nil, fmt.Errorf("mkdir user-data-dir: %w", err)
	}

	// Find the chromium binary
	resolved, err := findChromium(binary)
	if err != nil {
		_ = os.RemoveAll(dataDir)
		return nil, err
	}

	// Build the args. The key flags:
	//   --headless=new           (modern headless)
	//   --no-sandbox              (required when running as root in CI)
	//   --disable-gpu             (no GPU in headless)
	//   --remote-debugging-port   (CDP)
	//   --user-data-dir           (isolated profile)
	//   --disable-extensions-except=<dist>  (allow only this extension)
	//   --load-extension=<dist>   (the actual extension)
	//   about:blank               (initial page)
	args := []string{
		"--headless=new",
		"--no-sandbox",
		"--disable-gpu",
		"--no-first-run",
		"--no-default-browser-check",
		// Accept self-signed certs on localhost (for the HTTPS mock).
		// This is the standard workaround for headless Chrome smoke tests.
		"--ignore-certificate-errors",
		// Suppress the "unsupported flag" warning for --ignore-certificate-errors-spki-list
		"--ignore-certificate-errors-spki-list=",
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--user-data-dir=" + dataDir,
		"--disable-extensions-except=" + distPath,
		"--load-extension=" + distPath,
		"about:blank",
	}
	cmd := exec.Command(resolved, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(dataDir)
		return nil, fmt.Errorf("start chromium: %w", err)
	}

	proc := &chromeProcess{cmd: cmd, dataDir: dataDir}
	if err := proc.waitForCDP(port, timeout); err != nil {
		_ = proc.close()
		return nil, err
	}
	return proc, nil
}

func findChromium(supplied string) (string, error) {
	if supplied != "" {
		if _, err := os.Stat(supplied); err == nil {
			return supplied, nil
		}
		return "", fmt.Errorf("chromium not found at %s", supplied)
	}
	candidates := []string{
		"chromium", "chromium-browser",
		"google-chrome", "google-chrome-stable",
		"/usr/bin/chromium", "/usr/bin/chromium-browser",
		"/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
	}
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path, nil
		}
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("chromium not found in $PATH and no --chromium supplied")
}

func (p *chromeProcess) waitForCDP(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("http://127.0.0.1:%d/json/version", port)
	consecutive := 0
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		consecutive++
		// If the process exited, fail fast
		if p.cmd.ProcessState != nil && p.cmd.ProcessState.Exited() {
			return fmt.Errorf("chromium exited before CDP became ready")
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("CDP port %d not ready after %s", port, timeout)
}

func (p *chromeProcess) close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	}
	if p.dataDir != "" {
		_ = os.RemoveAll(p.dataDir)
	}
	return nil
}

// findPortFromArgs extracts the --remote-debugging-port from chromium args.
// Not used here (we pass port explicitly) but kept for parity with the
// Platform's test-extension pattern.
func findPortFromArgs(args []string) int {
	for i, a := range args {
		if a == "--remote-debugging-port" && i+1 < len(args) {
			var p int
			fmt.Sscanf(args[i+1], "%d", &p)
			return p
		}
		if strings.HasPrefix(a, "--remote-debugging-port=") {
			var p int
			fmt.Sscanf(strings.TrimPrefix(a, "--remote-debugging-port="), "%d", &p)
			return p
		}
	}
	return 0
}
