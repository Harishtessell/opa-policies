package opa

import "embed"

//go:embed policies/*.rego policies/data.json
var policyFS embed.FS
