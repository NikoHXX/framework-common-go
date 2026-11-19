package enum

import "strings"

// UserType 用户类型，对齐 Java UserType。
type UserType struct {
	Code string
}

// 用户类型枚举实例。
var (
	UserTypeSys     = UserType{Code: "sys_user"}
	UserTypeIndex   = UserType{Code: "index_user"}
	UserTypeCompany = UserType{Code: "company_user"}
	UserTypePerson  = UserType{Code: "person_user"}
	UserTypeApp     = UserType{Code: "app_user"}
)

// AllUserTypes 全部已知用户类型（注册/解析用）。
var AllUserTypes = []UserType{
	UserTypeSys, UserTypeIndex, UserTypeCompany, UserTypePerson, UserTypeApp,
}

// ParseUserType 按字符串包含匹配用户类型，对齐 Java UserType.getUserType。
// 未匹配返回零值与 false。
func ParseUserType(raw string) (UserType, bool) {
	for _, ut := range AllUserTypes {
		if strings.Contains(raw, ut.Code) {
			return ut, true
		}
	}
	return UserType{}, false
}
