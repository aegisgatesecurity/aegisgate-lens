module github.com/aegisgatesecurity/aegisgate-lens/tools/headless-smoke

go 1.25

// Only one third-party dep: gorilla/websocket, used for CDP
// communication. Mirrors the Platform's test-extension pattern.
require github.com/gorilla/websocket v1.5.3
