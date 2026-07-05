// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens v0.1.0-beta - Headless Smoke Test: Test runner

// Runs test cases against the Lens in a real browser via CDP.
// For each case, types the prompt into the mock textarea, waits for
// the content script to fire, and reads window.__lens_cs.lastDetections
// plus the banner DOM.
package main

import (
	"encoding/json"
	"log"
	"fmt"
	"time"
)

type TestResult struct {
	Name           string   `json:"name"`
	Prompt         string   `json:"prompt"`
	ShouldDetect   bool     `json:"should_detect"`
	ExpectedCategory string `json:"expected_category,omitempty"`
	DetectionCount int      `json:"detection_count"`
	Categories     []string `json:"categories,omitempty"`
	BannerCount    int      `json:"banner_count"`
	BannerText     string   `json:"banner_text,omitempty"`
	ProviderID     string   `json:"provider_id,omitempty"`
	InputFound     bool     `json:"input_found"`
	TAValue        string   `json:"ta_value,omitempty"`
	DirectTest     interface{} `json:"direct_test,omitempty"`
	Passed         bool     `json:"passed"`
	Error          string   `json:"error,omitempty"`
}

func runTestCases(cdp *CDPClient, target cdpTarget, cases []TestCase, timeout time.Duration) []TestResult {
	results := make([]TestResult, 0, len(cases))
	for _, tc := range cases {
		r := runOneCase(cdp, target, tc, timeout)
		results = append(results, r)
	}
	return results
}

func runOneCase(cdp *CDPClient, target cdpTarget, tc TestCase, timeout time.Duration) TestResult {
	r := TestResult{
		Name:             tc.Name,
		Prompt:           tc.Prompt,
		ShouldDetect:     tc.ShouldDetect,
		ExpectedCategory: tc.ExpectedCategory,
	}

	// Step 1: Clear the textarea and set the new prompt
	clearAndType := fmt.Sprintf(`
		(function() {
			const ta = document.getElementById('prompt-textarea');
			if (!ta) return { error: 'no textarea' };
			// Clear
			ta.value = '';
			ta.dispatchEvent(new Event('input', { bubbles: true }));
			// Set new value
			ta.value = %q;
			ta.dispatchEvent(new Event('input', { bubbles: true }));
			return { ok: true };
		})()
	`, tc.Prompt)
	_, err := cdp.evaluate(clearAndType, false)
	if err != nil {
		r.Error = fmt.Sprintf("clear/type: %v", err)
		return r
	}

	// Step 2: Wait for the content script's debounce (200ms) + detector run
	time.Sleep(500 * time.Millisecond)

	// Step 3: Read window.__lens_cs.lastDetections
	readState := `
		(function() {
			const cs = window.__lens_cs;
			if (!cs) return JSON.stringify({ error: '__lens_cs undefined' });
			const dets = cs.lastDetections || [];
			const banners = document.querySelectorAll('[data-aegisgate-lens="banner"]');
			const visibleBanners = Array.from(banners).filter(b => b.style.display !== 'none');
			const ta = document.getElementById('prompt-textarea');
			const directResult = (function() {
				try {
					const d = window.__lensDispatcher;
					if (!d) return 'dispatcher undefined';
					const facets = (d.listFacets && d.listFacets()) || [];
					const r = d.detect('My SSN is 123-45-6789 and email is test@example.com');
					return {
						facets: facets,
						detectIsArray: Array.isArray(r),
						detectEvents: r && r.events ? r.events.length : null,
						detectCount: r && typeof r.count === 'number' ? r.count : null,
						detectSample: r && r.events && r.events[0] ? JSON.stringify(r.events[0]).substring(0, 200) : null
					};
				} catch (e) { return 'error: ' + e.message; }
			})();
			return {
				detection_count: dets.length,
				categories: dets.map(d => d.category || d.facet),
				banner_count: visibleBanners.length,
				banner_text: visibleBanners.length > 0 ? visibleBanners[0].textContent.substring(0, 200) : '',
				provider_id: cs.provider ? cs.provider.id : null,
				input_found: !!ta,
				ta_value: ta ? ta.value : null,
				direct_test: directResult
			};
		})()
	`
	// DEBUG: check the page state right before reading
	debugRes, _ := cdp.evaluate(`(function() {
		return JSON.stringify({
			bodyExists: !!document.body,
			textareaExists: !!document.getElementById('prompt-textarea'),
			allTextareas: document.querySelectorAll('textarea').length,
			bodyHTML: document.body ? document.body.innerHTML.substring(0, 500) : null,
			url: window.location.href
		});
	})()`, false)
	log.Printf("    debug page state: %s", string(debugRes))
	res, err := cdp.evaluate(readState, false)
	if err != nil {
		r.Error = fmt.Sprintf("read state: %v", err)
		return r
	}

	// Parse the result (it's a JSON string because of returnByValue)
	var state struct {
		Error         string   `json:"error"`
		DetectionCount int      `json:"detection_count"`
		Categories     []string `json:"categories"`
		BannerCount    int      `json:"banner_count"`
		BannerText     string   `json:"banner_text"`
		ProviderID     string   `json:"provider_id"`
		InputFound     bool     `json:"input_found"`
		TAValue        string   `json:"ta_value"`
		PDState        *struct {
			Provider string `json:"provider"`
			HasInput  bool   `json:"hasInput"`
			LastValue string `json:"lastValue"`
		} `json:"pd_state"`
		DirectTest     interface{} `json:"direct_test"`
	}
	if err := json.Unmarshal(res, &state); err != nil {
		r.Error = fmt.Sprintf("parse state: %v (raw=%s)", err, string(res))
		return r
	}
	if state.Error != "" {
		r.Error = state.Error
		return r
	}

	r.DetectionCount = state.DetectionCount
	r.Categories = state.Categories
	r.BannerCount = state.BannerCount
	r.BannerText = state.BannerText
	r.ProviderID = state.ProviderID
	r.InputFound = state.InputFound
	r.TAValue = state.TAValue
	r.DirectTest = state.DirectTest

	// Step 4: Assert
	if tc.ShouldDetect {
		r.Passed = r.DetectionCount > 0 && r.BannerCount > 0
		if !r.Passed {
			if r.DetectionCount == 0 {
				r.Error = "expected detection but got 0"
			} else if r.BannerCount == 0 {
				r.Error = "detection present but banner not visible"
			}
		}
	} else {
		r.Passed = r.DetectionCount == 0
		if !r.Passed {
			r.Error = fmt.Sprintf("expected 0 detections (benign) but got %d: %v", r.DetectionCount, r.Categories)
		}
	}
	return r
}

func buildReport(results []TestResult, passed, failed int) []byte {
	report := map[string]interface{}{
		"test_name": "AegisGate Lens v0.1.0-beta - Headless Smoke",
		"date":      time.Now().Format(time.RFC3339),
		"total":     len(results),
		"passed":    passed,
		"failed":    failed,
		"results":   results,
	}
	out, _ := json.MarshalIndent(report, "", "  ")
	return out
}
