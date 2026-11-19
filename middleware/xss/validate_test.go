package xss

import "testing"

func TestContainsHTML(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"普通昵称", false},
		{"<script>alert(1)</script>", true},
		{"hello<br>", true},
		{"a < b", false},
	}
	for _, tc := range cases {
		if got := ContainsHTML(tc.in); got != tc.want {
			t.Errorf("ContainsHTML(%q)=%v want %v", tc.in, got, tc.want)
		}
	}
}
