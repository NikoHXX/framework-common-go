package sms

// 已对接发信的厂商 code（与 NewSender 一致）。
// 管理端下拉只暴露这些，避免选了未实现厂商。
const (
	SupplierAlibaba = "alibaba"
	SupplierHuawei  = "huawei"
	SupplierTencent = "tencent"
	SupplierYunpian = "yunpian"
)

// suppliers 已对接厂商枚举表，对齐 Java SupplierEnum 的「可选项」语义，
// 但 Go 侧只收录真实可发信的厂商（非 sms4j 全量清单）。
var suppliers = []SupplierOption{
	{Label: "阿里", Value: SupplierAlibaba},
	{Label: "腾讯", Value: SupplierTencent},
	{Label: "云片", Value: SupplierYunpian},
	{Label: "华为", Value: SupplierHuawei},
}

// SupplierOption 管理端厂商下拉项。
type SupplierOption struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// SupplierSelectList 已对接厂商列表，对齐 Java SupplierEnum.toSelectList 的用法。
func SupplierSelectList() []SupplierOption {
	out := make([]SupplierOption, len(suppliers))
	copy(out, suppliers)
	return out
}

// SupplierLabel 按 value 反查中文名；未知则返回原 value。
func SupplierLabel(value string) string {
	for _, o := range suppliers {
		if o.Value == value {
			return o.Label
		}
	}
	return value
}
