package events

import (
	"net/http"
	"testing"
)

func TestDecisionConstructors(t *testing.T) {
	if got := Continue(); got.Kind != DecisionKindContinue {
		t.Fatalf("Continue() Kind = %v, want %v", got.Kind, DecisionKindContinue)
	}
	b := Block(http.StatusForbidden, "no")
	if b.Kind != DecisionKindBlock || b.BlockStatus != http.StatusForbidden || b.BlockMessage != "no" {
		t.Fatalf("Block() = %+v", b)
	}
	m := RequireMfa("u", "s")
	if m.Kind != DecisionKindRequireMfa || m.UserID != "u" || m.PendingSessionID != "s" {
		t.Fatalf("RequireMfa() = %+v", m)
	}
}
