// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"
	"time"
)

func TestDurationEnv(t *testing.T) {
	t.Setenv("JESS_TEST_DUR", "")
	if got := durationEnv("JESS_TEST_DUR", 5*time.Minute); got != 5*time.Minute {
		t.Errorf("unset -> %v, want default 5m", got)
	}
	t.Setenv("JESS_TEST_DUR", "90s")
	if got := durationEnv("JESS_TEST_DUR", time.Minute); got != 90*time.Second {
		t.Errorf("90s -> %v, want 90s", got)
	}
	t.Setenv("JESS_TEST_DUR", "120") // bare seconds
	if got := durationEnv("JESS_TEST_DUR", time.Minute); got != 120*time.Second {
		t.Errorf("120 -> %v, want 120s", got)
	}
	t.Setenv("JESS_TEST_DUR", "garbage")
	if got := durationEnv("JESS_TEST_DUR", 7*time.Minute); got != 7*time.Minute {
		t.Errorf("garbage -> %v, want default 7m", got)
	}
}
