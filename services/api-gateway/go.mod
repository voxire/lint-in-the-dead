module github.com/voxire/lint-in-the-dead/services/api-gateway

go 1.24

require (
	github.com/voxire/lint-in-the-dead/pkg v0.0.0
	github.com/gorilla/websocket v1.5.3
)

replace github.com/voxire/lint-in-the-dead/pkg => ../../pkg
