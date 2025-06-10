package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

// PolicyEngine holds preloaded modules and data for reuse
type PolicyEngine struct {
	modules []func(*rego.Rego)
	data    map[string]interface{}
}

// NewPolicyEngine loads Rego modules and data.json
func NewPolicyEngine() (*PolicyEngine, error) {
	var modules []func(*rego.Rego)

	// Load all .rego files from embedded FS
	err := fs.WalkDir(policyFS, "policies", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".rego" {
			content, err := policyFS.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", path, err)
			}
			modules = append(modules, rego.Module(path, string(content)))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("rego file loading failed: %w", err)
	}

	// Load data.json
	dataBytes, err := policyFS.ReadFile("policies/data.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read data.json: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(dataBytes, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data.json: %w", err)
	}

	return &PolicyEngine{
		modules: modules,
		data:    data,
	}, nil
}

func (pe *PolicyEngine) EvaluateQuery(ctx context.Context, query string, input map[string]interface{}) (interface{}, error) {
	store := inmem.NewFromObject(pe.data)

	// Create rego options for modules
	var regoOptions []func(*rego.Rego)

	regoOptions = append(regoOptions, rego.Query(query))
	regoOptions = append(regoOptions, rego.Input(input))
	regoOptions = append(regoOptions, rego.Store(store))

	// Add all preloaded rego.Module(...) options
	regoOptions = append(regoOptions, pe.modules...)

	// Create and evaluate
	r := rego.New(regoOptions...)

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("OPA evaluation error: %w", err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("OPA returned empty result")
	}

	return rs[0].Expressions[0].Value, nil
}
