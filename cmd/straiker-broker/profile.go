package main

import (
	"github.com/straiker-ai/straiker-broker/pkg/config"
	"github.com/straiker-ai/straiker-broker/pkg/service"
)

// profile is what makes the shared agent (pkg/) Straiker Broker's: its names, its environments and where it keeps things.
var profile = &config.Profile{
	Name:      "straiker-broker",
	EnvPrefix: "BROKER_",
	// Built in, so a customer configures only their org id and allowlist. Stage and prod are added with the
	// broker-relay's host key for each, which the agent pins: an environment without one is never listed.
	Environments: map[string]config.Environment{
		"dev": {
			Relay:   "wss://broker.dev.straiker.ai",
			HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGMwv9358a+DxXGIaL/IkmuhRdX4tQZEkGOxFJoNJX2J",
		},
	},
	DefaultEnv:   "dev",
	TargetSuffix: "brk.straiker.ai",
	Register:     "register it in the Straiker console under Connect > Straiker Broker",
	ConfigFile:   "/etc/straiker/broker.yaml",
	SystemState:  "/var/lib/straiker-broker",
}

// serviceDef names the broker's service on each system.
var serviceDef = service.Def{
	Command:     "straiker-broker",
	Label:       "ai.straiker.broker",
	WindowsName: "StraikerBroker",
	Display:     "Straiker Broker",
	Description: "Lets Straiker reach AI apps in this network through one outbound HTTPS connection.",
	Docs:        "https://github.com/straiker-ai/straiker-broker",
}
