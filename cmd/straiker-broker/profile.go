package main

import (
	"github.com/straiker-ai/straiker-broker/pkg/config"
	"github.com/straiker-ai/straiker-broker/pkg/relays"
	"github.com/straiker-ai/straiker-broker/pkg/service"
)

// profile is what makes the shared agent (pkg/) Straiker Broker's: its names, its environments and where it keeps things.
var profile = &config.Profile{
	Name:      "straiker-broker",
	EnvPrefix: "BROKER_",
	// Built in, so a customer configures only their org id and allowlist; shared with every agent that connects
	// through Straiker Broker (pkg/relays).
	Environments: relays.Environments(),
	DefaultEnv:   relays.DefaultEnv,
	TargetSuffix: relays.TargetSuffix,
	Register:     "register it with Straiker (for MCP scans: straiker mcp tunnel create --agent-key <key>; otherwise your Straiker contact)",
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
