
// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens v0.2.0 - Headless Smoke Test: CDP client (gorilla/websocket)

// Chrome DevTools Protocol client. Uses gorilla/websocket.
// Mirrors the pattern in the AegisGate Platform test infrastructure (separate repo)
// but is simplified for the smoke test only.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// CDPClient is a minimal Chrome DevTools Protocol client.
type CDPClient struct {
	wsURL     string
	conn      *websocket.Conn
	mu        sync.Mutex
	nextID    int
	pending   map[int]chan json.RawMessage
	events    chan json.RawMessage
	closeEv   chan struct{}
	closed    bool
	closeOnce sync.Once
	timeout   time.Duration
}

type cdpTarget struct {
	Type string `json:"type"`
	URL  string `json:"url"`
	WS   string `json:"webSocketDebuggerUrl"`
}

func newCDPClient(port int, timeout time.Duration) (*CDPClient, cdpTarget, error) {
	// Get the browser-level WS URL from /json/version
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json/version", port))
	if err != nil {
		return nil, cdpTarget{}, fmt.Errorf("GET /json/version: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var v struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, cdpTarget{}, fmt.Errorf("parse /json/version: %w (body=%s)", err, string(body))
	}
	// Get all targets and pick the first page
	tgResp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json/list", port))
	if err != nil {
		return nil, cdpTarget{}, fmt.Errorf("GET /json/list: %w", err)
	}
	defer tgResp.Body.Close()
	tgBody, _ := io.ReadAll(tgResp.Body)
	var targets []cdpTarget
	if err := json.Unmarshal(tgBody, &targets); err != nil {
		return nil, cdpTarget{}, fmt.Errorf("parse /json/list: %w", err)
	}
	// Find the page target
	var pageWS string
	var pageTarget cdpTarget
	for _, t := range targets {
		if t.Type == "page" {
			pageWS = t.WS
			pageTarget = t
			break
		}
	}
	if pageWS == "" {
		return nil, cdpTarget{}, fmt.Errorf("no page target found in /json/list")
	}

	// Connect to the page-level WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(pageWS, nil)
	if err != nil {
		return nil, cdpTarget{}, fmt.Errorf("dial CDP: %w", err)
	}

	c := &CDPClient{
		wsURL:   pageWS,
		conn:    conn,
		nextID:  1,
		pending: make(map[int]chan json.RawMessage),
		events:  make(chan json.RawMessage, 64),
		closeEv: make(chan struct{}),
		timeout: timeout,
	}
	go c.readLoop()
	return c, pageTarget, nil
}

func (c *CDPClient) close() error {
	// Use sync.Once to make the close idempotent. The previous version
	// had a double-close bug: close() did close(c.closeEv) AND
	// readLoop() also did close(c.closeEv) on conn error, causing
	// "panic: close of closed channel" (goroutine leak at shutdown).
	c.closeOnce.Do(func() {
		c.closed = true
		close(c.closeEv)
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
	return nil
}

// send sends a CDP method call and returns the response.
func (c *CDPClient) send(method string, params interface{}) (json.RawMessage, error) {
	c.mu.Lock()
	id := c.nextID
	c.nextID++
	ch := make(chan json.RawMessage, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	msg := map[string]interface{}{
		"id":     id,
		"method": method,
		"params": params,
	}
	data, _ := json.Marshal(msg)
	if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		return nil, fmt.Errorf("ws write: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	select {
	case resp := <-ch:
		// Check for error
		var r struct {
			Error  *struct{ Code int; Message string } `json:"error"`
			Result json.RawMessage                       `json:"result"`
		}
		if err := json.Unmarshal(resp, &r); err != nil {
			return nil, fmt.Errorf("unmarshal response: %w", err)
		}
		if r.Error != nil {
			return nil, fmt.Errorf("CDP error: %s", r.Error.Message)
		}
		return r.Result, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("CDP timeout waiting for %s", method)
	}
}

// RuntimeEvaluate runs a JS expression in the page's main world
// and returns the result. If awaitPromise is true, waits for the
// promise to resolve.
func (c *CDPClient) evaluate(expression string, awaitPromise bool) (json.RawMessage, error) {
	params := map[string]interface{}{
		"expression":    expression,
		"returnByValue": true,
		"awaitPromise":  awaitPromise,
	}
	res, err := c.send("Runtime.evaluate", params)
	if err != nil {
		return nil, err
	}
	var r struct {
		Result struct {
			Value          json.RawMessage `json:"value"`
			Type           string          `json:"type"`
			Description    string          `json:"description"`
		} `json:"result"`
	}
	if err := json.Unmarshal(res, &r); err != nil {
		return nil, err
	}
	log.Printf("evaluate type=%s desc=%s valueLen=%d", r.Result.Type, r.Result.Description, len(r.Result.Value))
	return r.Result.Value, nil
}

// setHostHeader sets the Host header for subsequent requests via
// Network.setExtraHTTPHeaders. This is the simplest way to override
// the Host header for a single page navigation. The Host header
// is used by the per-host mock server to serve the right DOM shape.
func (c *CDPClient) setHostHeader(host string) error {
    params := map[string]interface{}{
        "headers": map[string]interface{}{
            "Host": host,
        },
    }
    _, err := c.send("Network.setExtraHTTPHeaders", params)
    return err
}

// drainEvents empties the events channel of any pending events.
// Called before each navigate to prevent the channel from being
// backed up with stale events (e.g., evaluate events from prior
// bundle injection or reset calls), which can block subsequent
// CDP requests like Page.enable.
func (c *CDPClient) drainEvents() {
	drained := 0
	for {
		select {
		case <-c.events:
			drained++
		case <-c.closeEv:
			return
		case <-time.After(50 * time.Millisecond):
			return
		}
	}
}

func (c *CDPClient) navigate(target cdpTarget, url string, timeout time.Duration) error {
	// Drain any pending events first to prevent channel backup
	c.drainEvents()
	if _, err := c.send("Page.enable", nil); err != nil {
		return err
	}
	// Navigate and wait for load
	_, err := c.send("Page.navigate", map[string]interface{}{"url": url})
	if err != nil {
		return err
	}
	// Wait for load event
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ev, ok := <-c.events
		if !ok {
			return fmt.Errorf("event channel closed")
		}
		var evt struct {
			Method string                 `json:"method"`
			Params map[string]interface{} `json:"params"`
		}
		if err := json.Unmarshal(ev, &evt); err != nil {
			continue
		}
		if evt.Method == "Page.loadEventFired" {
			return nil
		}
	}
	return fmt.Errorf("timeout waiting for Page.loadEventFired")
}

func (c *CDPClient) waitForGlobal(target cdpTarget, expr string, timeout time.Duration) error {
	// Poll for the global to exist. The check is: typeof <expr> !== 'undefined'
	check := fmt.Sprintf("typeof %s !== 'undefined'", expr)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		res, err := c.evaluate(check, false)
		if err == nil && string(res) == "true" {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s to be defined", expr)
}

func (c *CDPClient) getExtensionID(timeout time.Duration) (string, error) {
	// Query the service worker registration
	js := `(async () => {
		const mgr = (typeof browser !== 'undefined') ? browser : (typeof chrome !== 'undefined' ? chrome : null);
		if (!mgr || !mgr.management) return null;
		try {
			const info = await mgr.management.getSelf();
			return info ? info.id : null;
		} catch (e) { return null; }
	})()`
	res, err := c.evaluate(js, true)
	if err != nil {
		return "", err
	}
	// Result is a JSON string (because of returnByValue with awaitPromise)
	id := strings.Trim(string(res), "\"")
	return id, nil
}

func (c *CDPClient) readLoop() {
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			// The readLoop exits on conn error. The close() call will
			// handle closing closeEv (via sync.Once). We just return.
			return
		}
		var msg struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg.ID != 0 {
			c.mu.Lock()
			ch, ok := c.pending[msg.ID]
			if ok {
				delete(c.pending, msg.ID)
			}
			c.mu.Unlock()
			if ok {
				ch <- data
			}
		} else {
			// event
			select {
			case c.events <- data:
			default:
				// drop if buffer full
			}
		}
	}
}

// addScriptToEvaluateOnNewDocument reads the bundle from a file
// and injects it into the page's main world via Runtime.evaluate.
// The content_scripts manifest array does not fire reliably with
// --load-extension in headless mode. Runtime.evaluate runs the
// script immediately in the page's main world where window.__lens_cs
// will be visible to subsequent Runtime.evaluate calls.
func (c *CDPClient) addScriptToEvaluateOnNewDocument(target cdpTarget, scriptPath string, timeout time.Duration) error {
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	if _, err := c.evaluate(string(scriptBytes), false); err != nil {
		return fmt.Errorf("evaluate bundle: %w", err)
	}
	return nil
}

// reloadPage reloads the current page.
func (c *CDPClient) reloadPage(target cdpTarget, timeout time.Duration) error {
	if _, err := c.send("Page.enable", nil); err != nil {
		return err
	}
	_, err := c.send("Page.reload", map[string]interface{}{"ignoreCache": true})
	return err
}

// clickSelector clicks the first element matching the given CSS
// selector in the page's main world. Uses the DOM API el.click()
// (not synthetic mouse events) which dispatches a real click event
// that the banner event listeners respond to correctly.
//
// Returns nil if the click was dispatched, or an error if no
// element matched the selector.
//
// Used by the dismiss flow test (B1-D1).
func (c *CDPClient) clickSelector(selector string) error {
	escapedSelector, err := json.Marshal(selector)
	if err != nil {
		return fmt.Errorf("escape selector: %w", err)
	}
	js := fmt.Sprintf(`(function() {
		var el = document.querySelector(%s);
		if (!el) return { error: 'no element matched selector' };
		el.click();
		return { ok: true, tag: el.tagName, className: el.className };
	})()`, string(escapedSelector))
	res, err := c.evaluate(js, false)
	if err != nil {
		return fmt.Errorf("evaluate click: %w", err)
	}
	var r struct {
		Error     string `json:"error"`
		OK        bool   `json:"ok"`
		Tag       string `json:"tag"`
		ClassName string `json:"className"`
	}
	if err := json.Unmarshal(res, &r); err != nil {
		return fmt.Errorf("unmarshal click result: %w (raw=%s)", err, string(res))
	}
	if r.Error != "" {
		return fmt.Errorf("click failed: %s", r.Error)
	}
	return nil
}

