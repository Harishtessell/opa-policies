package embed

import "embed"

//go:embed *.rego data.json
var FS embed.FS
