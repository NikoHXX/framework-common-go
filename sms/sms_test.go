package sms

import (
	"errors"
	"testing"
)

func TestIsSupported(t *testing.T) {
	if !IsSupported("alibaba") || !IsSupported("TENCENT") {
		t.Fatal("expected alibaba/tencent supported")
	}
	if IsSupported("cloopen") {
		t.Fatal("cloopen not implemented yet")
	}
}

func TestNewSenderUnsupported(t *testing.T) {
	_, err := NewSender("cloopen", Credentials{})
	if !errors.Is(err, ErrUnsupportedSupplier) {
		t.Fatalf("want ErrUnsupportedSupplier, got %v", err)
	}
}

func TestSupplierSelectList(t *testing.T) {
	list := SupplierSelectList()
	if len(list) != 4 {
		t.Fatalf("want 4 integrated suppliers, got %d", len(list))
	}
	if SupplierLabel("alibaba") != "阿里" {
		t.Fatalf("label alibaba = %q", SupplierLabel("alibaba"))
	}
	supported := SupportedSuppliers()
	if len(supported) != len(list) {
		t.Fatalf("SupportedSuppliers=%d SelectList=%d", len(supported), len(list))
	}
}

func TestOrderedParamValues(t *testing.T) {
	got := orderedParamValues(SendRequest{Params: map[string]string{"b": "2", "a": "1"}})
	if len(got) != 2 || got[0] != "1" || got[1] != "2" {
		t.Fatalf("got %v", got)
	}
	got = orderedParamValues(SendRequest{ParamValues: []string{"x", "y"}})
	if len(got) != 2 || got[0] != "x" {
		t.Fatalf("got %v", got)
	}
}
