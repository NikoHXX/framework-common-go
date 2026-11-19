package sms

// 厂商 code，与 Java SupplierEnum / 管理端下拉 value 一致。
const (
	SupplierAlibaba   = "alibaba"
	SupplierCloopen   = "cloopen"
	SupplierCtyun     = "ctyun"
	SupplierEmay      = "emay"
	SupplierHuawei    = "huawei"
	SupplierJdcloud   = "jdcloud"
	SupplierNetease   = "netease"
	SupplierTencent   = "tencent"
	SupplierUnisms    = "unisms"
	SupplierYunpian   = "yunpian"
	SupplierZhutong   = "zhutong"
	SupplierLianlu    = "lianlu"
	SupplierDingzhong = "dingzhong"
	SupplierQiniu     = "qiniu"
	SupplierChuanglan = "chuanglan"
	SupplierJiguang   = "jiguang"
	SupplierBudingV2  = "buding_v2"
	SupplierMas       = "mas"
	SupplierBaidu     = "baidu"
	SupplierLuosimao  = "luosimao"
	SupplierMysubmail = "mysubmail"
	SupplierDanmi     = "danmi"
)

// SupplierOption 管理端厂商下拉项。
type SupplierOption struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// SupplierSelectList 全部可选厂商，对齐 Java SupplierEnum.toSelectList。
func SupplierSelectList() []SupplierOption {
	return []SupplierOption{
		{Label: "阿里", Value: SupplierAlibaba},
		{Label: "容联云", Value: SupplierCloopen},
		{Label: "天翼云", Value: SupplierCtyun},
		{Label: "亿美软通", Value: SupplierEmay},
		{Label: "华为", Value: SupplierHuawei},
		{Label: "京东", Value: SupplierJdcloud},
		{Label: "网易", Value: SupplierNetease},
		{Label: "腾讯", Value: SupplierTencent},
		{Label: "合一", Value: SupplierUnisms},
		{Label: "云片", Value: SupplierYunpian},
		{Label: "助通", Value: SupplierZhutong},
		{Label: "联麓", Value: SupplierLianlu},
		{Label: "鼎众", Value: SupplierDingzhong},
		{Label: "七牛云", Value: SupplierQiniu},
		{Label: "创蓝", Value: SupplierChuanglan},
		{Label: "极光", Value: SupplierJiguang},
		{Label: "布丁云V2", Value: SupplierBudingV2},
		{Label: "中国移动 云MAS", Value: SupplierMas},
		{Label: "百度云 sms", Value: SupplierBaidu},
		{Label: "螺丝帽 sms", Value: SupplierLuosimao},
		{Label: "SUBMAIL sms", Value: SupplierMysubmail},
		{Label: "danmi sms", Value: SupplierDanmi},
	}
}

// SupplierLabel 按 value 反查中文名；未知则返回原 value。
func SupplierLabel(value string) string {
	for _, o := range SupplierSelectList() {
		if o.Value == value {
			return o.Label
		}
	}
	return value
}
