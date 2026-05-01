module github.com/voxire/lint-in-the-dead/tests/integration

go 1.24

require (
	github.com/voxire/lint-in-the-dead/pkg v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/voxire/lint-in-the-dead/pkg => ../../pkg
