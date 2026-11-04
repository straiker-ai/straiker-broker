package openshell

import (
	"testing"

	"github.com/straiker-ai/straiker-broker/pkg/guard"
)

func TestTheGatewaysSettingsAreChecked(t *testing.T) {
	ok := map[string]string{keyGatewayID: "gw-1", keyGatewayJWKS: "/etc/openshell/jwks.json", keyAudience: DefaultAudience}
	if err := (Adapter{}).Validate(ok); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(map[string]string){
		"no gateway id":    func(s map[string]string) { s[keyGatewayID] = "" },
		"a bad gateway id": func(s map[string]string) { s[keyGatewayID] = "gw 1" },
		"no gateway keys":  func(s map[string]string) { s[keyGatewayJWKS] = "" },
		"plain-http keys":  func(s map[string]string) { s[keyGatewayJWKS] = "http://gw/.well-known/jwks.json" },
		"two audiences":    func(s map[string]string) { s[keyAudience] = "a b" },
	} {
		s := map[string]string{}
		for k, v := range ok {
			s[k] = v
		}
		edit(s)
		if err := (Adapter{}).Validate(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTheGatewaysSettingsKeepTheirFlagsAndDefaults(t *testing.T) {
	flags := map[string]guard.Setting{}
	for _, s := range (Adapter{}).Settings() {
		flags[s.Flag] = s
	}
	for _, f := range []string{"gateway-id", "gateway-jwks", "audience"} {
		if _, ok := flags[f]; !ok {
			t.Errorf("--%s is gone: the guard's documented command line must not change", f)
		}
	}
	if flags["audience"].Default != DefaultAudience || !flags["gateway-jwks"].Path {
		t.Fatalf("%+v", flags)
	}
	if (Adapter{}).Ingress() != "gw-openshell" {
		t.Fatal("Defend reads OpenShell traffic as gw-openshell")
	}
}
