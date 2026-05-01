module github.com/voxire/lint-in-the-dead/services/audit-service

go 1.24

require (
	github.com/voxire/lint-in-the-dead/pkg v0.0.0
	github.com/lib/pq v1.10.9
)

replace github.com/voxire/lint-in-the-dead/pkg => ../../pkg
