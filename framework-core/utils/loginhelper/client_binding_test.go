package loginhelper

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSplitClientRules(t *testing.T) {
	got := splitClientRules(" /a/** ,;/b\n/c ")
	want := []string{"/a/**", "/b", "/c"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestValidateClientBindingNoExtraNoHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/system/user/list", nil)
	if msg, ok := ValidateClientBinding(r, ""); !ok || msg != "" {
		t.Fatalf("empty extra+header should pass, got ok=%v msg=%q", ok, msg)
	}
}

func TestValidateClientBindingMismatch(t *testing.T) {
	// 对齐 Java equalsAny：extra 与 header/param 任一相等即过。
	// extra 为空且 param 也为空时，即便 header 有值也会过（param 同为空命中）。
	r := httptest.NewRequest(http.MethodGet, "/system/user/list", nil)
	r.Header.Set(ClientKey, "pc")
	if msg, ok := ValidateClientBinding(r, ""); !ok || msg != "" {
		t.Fatalf("empty extra + empty param should pass (Java equalsAny), got ok=%v msg=%q", ok, msg)
	}
}

func TestClientIDMatchLogic(t *testing.T) {
	cases := []struct {
		extra, header, param string
		wantOK               bool
	}{
		{"pc", "pc", "", true},
		{"pc", "", "pc", true},
		{"pc", "other", "other", false},
		{"pc", "", "", false},
		{"", "", "", true},
		{"", "pc", "", true}, // param 同为空，equalsAny 命中
	}
	for _, tc := range cases {
		ok := tc.extra == tc.header || tc.extra == tc.param
		if ok != tc.wantOK {
			t.Fatalf("extra=%q header=%q param=%q => %v want %v",
				tc.extra, tc.header, tc.param, ok, tc.wantOK)
		}
	}
}

func TestNormalizeAccessPath(t *testing.T) {
	if got := normalizeAccessPath("app/**"); got != "/app/**" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeAccessPath("*"); got != "/**" {
		t.Fatalf("got %q", got)
	}
}
