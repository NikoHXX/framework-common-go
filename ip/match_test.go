package ip

import "testing"

func TestMatchRule(t *testing.T) {
	cases := []struct {
		rule, ip string
		want     bool
	}{
		{"192.168.1.10", "192.168.1.10", true},
		{"192.168.1.10", "192.168.1.11", false},
		{"192.168.*.?", "192.168.1.8", true},
		{"10.0.0.0/8", "10.20.30.40", true},
		{"10.0.0.0/8", "11.20.30.40", false},
		{" ", "10.0.0.1", false},
		{"10.0.0.1", "", false},
	}
	for _, tc := range cases {
		if got := MatchRule(tc.rule, tc.ip); got != tc.want {
			t.Errorf("MatchRule(%q, %q) = %v, want %v", tc.rule, tc.ip, got, tc.want)
		}
	}
}
