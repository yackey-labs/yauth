package yauth_test

import "testing"

// Deliberately failing test to prove branch protection blocks a red merge.
func TestProtectionCanary(t *testing.T) { t.Fatal("intentional failure: protection check") }
