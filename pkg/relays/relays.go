// Package relays is Straiker Broker's built-in network: each environment's relay, the SSH host key its agents pin and
// the Straiker API (the guard's), and the domain Straiker reaches a target under. Every agent that connects through Straiker Broker uses these, so
// they live here rather than in one command's profile.
package relays

import "github.com/straiker-ai/straiker-broker/pkg/config"

// DefaultEnv is the environment used when neither a relay nor an environment is given.
const DefaultEnv = "prod"

// TargetSuffix is the domain Straiker reaches a broker target under: <host>.<suffix>.
const TargetSuffix = "brk.straiker.ai"

// Environments are the relays by environment name. Each call returns a new map, so a caller cannot change the pins.
func Environments() map[string]config.Environment {
	return map[string]config.Environment{
		"dev": {
			Relay:   "wss://broker.dev.straiker.ai",
			API:     "https://api.dev.straiker.ai",
			HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGMwv9358a+DxXGIaL/IkmuhRdX4tQZEkGOxFJoNJX2J",
		},
		"stage": {
			Relay:   "wss://broker.stage.straiker.ai",
			API:     "https://api.stage.straiker.ai",
			HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEr6fa9H5wVGWwztKRYWRd7Ih3fIE/1omc0tXY058//u",
		},
		"prod": {
			Relay:   "wss://broker.prod.straiker.ai",
			API:     "https://api.prod.straiker.ai",
			HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOnEHRPDE0nEYTyisHLYPhmnb1JZIfiBqTR0BXDwON2x",
		},
	}
}
