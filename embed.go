package embed

import "embed"

//go:embed policies/*.rego policies/data.json
var FS embed.FS
