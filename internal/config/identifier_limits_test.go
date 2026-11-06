package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestMappedKeyIDByteLimits(t *testing.T) {
	for i, keyID := range []string{strings.Repeat("k", 128), strings.Repeat("é", 64), strings.Repeat("k", 129), strings.Repeat("é", 64) + "k"} {
		for _, multiple := range []bool{false, true} {
			t.Run(fmt.Sprintf("case%d/multiple=%t", i, multiple), func(t *testing.T) {
				useValidConfig(t)
				keys := map[string]string{keyID: "secret"}
				if multiple {
					keys["other"] = "second"
				}
				encoded, err := json.Marshal(keys)
				if err != nil {
					t.Fatal(err)
				}
				HMACKeysJSON = string(encoded)
				err = Initialize(nil)
				if len(keyID) > 128 {
					if err == nil || !strings.Contains(err.Error(), "128 bytes") {
						t.Fatalf("oversized ID error=%v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if GetHMACSecret(keyID) != "secret" {
					t.Fatal("explicit boundary key rejected")
				}
				omitted := GetHMACSecret("")
				if multiple && omitted != "" {
					t.Fatal("ambiguous omitted ID accepted")
				}
				if !multiple && omitted != "secret" {
					t.Fatal("single-key omitted ID no longer works")
				}
			})
		}
	}
}
