package excelhelper

import "sync"

// DictProvider 按字典类型取 value→label。由业务侧注入（读 sys_dict_data）。
// 返回 nil/空 map 时回落字段上的静态 excelDict。
type DictProvider func(dictType string) map[string]string

var (
	dictMu       sync.RWMutex
	dictProvider DictProvider
)

// SetDictProvider 注册运行时字典翻译，对齐 Java @ExcelDictFormat(dictType=...)。
func SetDictProvider(p DictProvider) {
	dictMu.Lock()
	dictProvider = p
	dictMu.Unlock()
}

func lookupDict(dictType, raw string) (label string, ok bool) {
	if dictType == "" || raw == "" {
		return "", false
	}
	dictMu.RLock()
	p := dictProvider
	dictMu.RUnlock()
	if p == nil {
		return "", false
	}
	m := p(dictType)
	if len(m) == 0 {
		return "", false
	}
	lab, hit := m[raw]
	return lab, hit
}

func reverseDict(dictType, label string) (value string, ok bool) {
	if dictType == "" || label == "" {
		return "", false
	}
	dictMu.RLock()
	p := dictProvider
	dictMu.RUnlock()
	if p == nil {
		return "", false
	}
	m := p(dictType)
	for v, lab := range m {
		if lab == label {
			return v, true
		}
	}
	return "", false
}
