// Package gateways lists the gateways the guard serves: one adapter each. A new gateway adds its adapter package
// under pkg/guard and one entry here; nothing else changes.
package gateways

import (
	"fmt"
	"sort"

	"github.com/straiker-ai/straiker-broker/pkg/guard"
	"github.com/straiker-ai/straiker-broker/pkg/guard/openshell"
)

// Default is the gateway the guard serves when none is named.
const Default = "openshell"

var adapters = map[string]guard.Adapter{
	"openshell": openshell.Adapter{},
}

// Get is the adapter for gateway.
func Get(gateway string) (guard.Adapter, error) {
	if a, ok := adapters[gateway]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("the guard serves %v, not %q", Names(), gateway)
}

// Names are the gateways the guard serves, sorted.
func Names() []string {
	out := make([]string, 0, len(adapters))
	for n := range adapters {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
