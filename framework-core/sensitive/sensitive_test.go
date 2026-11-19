package sensitive

import (
	"testing"

	"github.com/NikoHXX/framework-common-go/framework-core/constant"
	"github.com/NikoHXX/framework-common-go/framework-core/model"
)

func TestPhone(t *testing.T) {
	if got := Phone("13812348000"); got != "138****8000" {
		t.Fatalf("got %q", got)
	}
	if got := Phone("123"); got != "123" {
		t.Fatalf("short %q", got)
	}
}

func TestEmail(t *testing.T) {
	if got := Email("admin@example.com"); got != "a****@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestShouldMask(t *testing.T) {
	if !ShouldMask(nil, "system:user:edit") {
		t.Fatal("nil user should mask")
	}
	admin := &model.LoginUser{UserID: constant.SuperAdminUserID}
	if ShouldMask(admin, "system:user:edit") {
		t.Fatal("super admin should not mask")
	}
	editor := &model.LoginUser{
		UserID:         2,
		MenuPermission: []string{"system:user:edit"},
	}
	if ShouldMask(editor, "system:user:edit") {
		t.Fatal("editor should not mask")
	}
	viewer := &model.LoginUser{
		UserID:         3,
		MenuPermission: []string{"system:user:list"},
	}
	if !ShouldMask(viewer, "system:user:edit") {
		t.Fatal("viewer should mask")
	}
}
