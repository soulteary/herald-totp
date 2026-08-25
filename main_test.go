package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/pterm/pterm"
)

func TestShowBanner(t *testing.T) {
	var output bytes.Buffer
	pterm.SetDefaultOutput(&output)
	defer pterm.SetDefaultOutput(os.Stdout)

	showBanner()
	if got := output.String(); !strings.Contains(got, "Herald TOTP") || !strings.Contains(got, "TOTP 2FA Service") {
		t.Fatalf("banner output = %q", got)
	}
}
