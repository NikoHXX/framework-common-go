package sms

// 已对接发信的厂商 code（与 NewSender / 下拉同源）。
const (
	SupplierAlibaba = "alibaba"
	SupplierHuawei  = "huawei"
	SupplierTencent = "tencent"
	SupplierYunpian = "yunpian"

	// ---- 以下厂商仅预留 code，与 Java SupplierEnum / sms4j 对齐；尚未实现 Sender ----
	// 需要时：实现对应 sender + 在 NewSender switch 登记 + 取消下面常量注释并加入 suppliers。
	// SupplierCloopen   = "cloopen"    // 容联云
	// SupplierCtyun     = "ctyun"      // 天翼云
	// SupplierEmay      = "emay"       // 亿美软通
	// SupplierJdcloud   = "jdcloud"    // 京东
	// SupplierNetease   = "netease"    // 网易
	// SupplierUnisms    = "unisms"     // 合一
	// SupplierZhutong   = "zhutong"    // 助通
	// SupplierLianlu    = "lianlu"     // 联麓
	// SupplierDingzhong = "dingzhong"  // 鼎众
	// SupplierQiniu     = "qiniu"      // 七牛云
	// SupplierChuanglan = "chuanglan"  // 创蓝
	// SupplierJiguang   = "jiguang"    // 极光
	// SupplierBudingV2  = "buding_v2"  // 布丁云V2
	// SupplierMas       = "mas"        // 中国移动 云MAS
	// SupplierBaidu     = "baidu"      // 百度云
	// SupplierLuosimao  = "luosimao"   // 螺丝帽
	// SupplierMysubmail = "mysubmail"  // SUBMAIL
	// SupplierDanmi     = "danmi"      // danmi
)

// suppliers 已对接厂商枚举表。
// 管理端下拉只暴露已实现发信的厂商；未对接项见上方注释，勿直接加入本表。
var suppliers = []SupplierOption{
	{Label: "阿里", Value: SupplierAlibaba},
	{Label: "腾讯", Value: SupplierTencent},
	{Label: "云片", Value: SupplierYunpian},
	{Label: "华为", Value: SupplierHuawei},
	// ---- 未对接，需要时再实现 Sender 并取消注释 ----
	// {Label: "容联云", Value: SupplierCloopen},
	// {Label: "天翼云", Value: SupplierCtyun},
	// {Label: "亿美软通", Value: SupplierEmay},
	// {Label: "京东", Value: SupplierJdcloud},
	// {Label: "网易", Value: SupplierNetease},
	// {Label: "合一", Value: SupplierUnisms},
	// {Label: "助通", Value: SupplierZhutong},
	// {Label: "联麓", Value: SupplierLianlu},
	// {Label: "鼎众", Value: SupplierDingzhong},
	// {Label: "七牛云", Value: SupplierQiniu},
	// {Label: "创蓝", Value: SupplierChuanglan},
	// {Label: "极光", Value: SupplierJiguang},
	// {Label: "布丁云V2", Value: SupplierBudingV2},
	// {Label: "中国移动 云MAS", Value: SupplierMas},
	// {Label: "百度云 sms", Value: SupplierBaidu},
	// {Label: "螺丝帽 sms", Value: SupplierLuosimao},
	// {Label: "SUBMAIL sms", Value: SupplierMysubmail},
	// {Label: "danmi sms", Value: SupplierDanmi},
}

// SupplierOption 管理端厂商下拉项。
type SupplierOption struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// SupplierSelectList 已对接厂商列表，用法对齐 Java SupplierEnum.toSelectList。
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
