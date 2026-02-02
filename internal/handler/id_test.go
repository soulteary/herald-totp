package handler

import (
	"strings"
	"testing"
)

func TestNewEnrollID(t *testing.T) {
	id, err := NewEnrollID()
	if err != nil {
		t.Fatalf("NewEnrollID: %v", err)
	}
	if !strings.HasPrefix(id, idPrefixEnroll) {
		t.Errorf("NewEnrollID = %q, want prefix %q", id, idPrefixEnroll)
	}
	if len(id) < len(idPrefixEnroll)+10 {
		t.Errorf("NewEnrollID too short: %q", id)
	}
	// Uniqueness
	id2, _ := NewEnrollID()
	if id == id2 {
		t.Error("NewEnrollID should produce unique IDs")
	}
}

func TestNewChallengeID(t *testing.T) {
	id, err := NewChallengeID()
	if err != nil {
		t.Fatalf("NewChallengeID: %v", err)
	}
	if !strings.HasPrefix(id, idPrefixChallenge) {
		t.Errorf("NewChallengeID = %q, want prefix %q", id, idPrefixChallenge)
	}
	id2, _ := NewChallengeID()
	if id == id2 {
		t.Error("NewChallengeID should produce unique IDs")
	}
}
