package ip

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

// MatchRule 判断 clientIP 是否命中单条 IP 规则，对齐 Java NetUtils.isMatchIpRule。
// 支持精确值、* / ? 通配与 CIDR。
func MatchRule(rule, clientIP string) bool {
	rule = strings.TrimSpace(rule)
	clientIP = strings.TrimSpace(clientIP)
	if rule == "" || clientIP == "" {
		return false
	}
	if rule == clientIP {
		return true
	}
	if strings.Contains(rule, "/") {
		return matchCIDR(rule, clientIP)
	}
	if strings.ContainsAny(rule, "*?") {
		escaped := regexp.QuoteMeta(rule)
		escaped = strings.ReplaceAll(escaped, `\*`, `.*`)
		escaped = strings.ReplaceAll(escaped, `\?`, `.`)
		re, err := regexp.Compile("^" + escaped + "$")
		if err != nil {
			return false
		}
		return re.MatchString(clientIP)
	}
	return false
}

func matchCIDR(cidr, clientIP string) bool {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return false
	}
	network := net.ParseIP(strings.TrimSpace(parts[0]))
	current := net.ParseIP(strings.TrimSpace(clientIP))
	if network == nil || current == nil {
		return false
	}
	prefix, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return false
	}
	network = toIPBytes(network)
	current = toIPBytes(current)
	if network == nil || current == nil || len(network) != len(current) {
		return false
	}
	maxPrefix := len(network) * 8
	if prefix < 0 || prefix > maxPrefix {
		return false
	}
	fullBytes := prefix / 8
	remainBits := prefix % 8
	for i := 0; i < fullBytes; i++ {
		if network[i] != current[i] {
			return false
		}
	}
	if remainBits == 0 {
		return true
	}
	mask := byte(0xFF << (8 - remainBits))
	return network[fullBytes]&mask == current[fullBytes]&mask
}

// toIPBytes 统一成 4 或 16 字节切片（IPv4 优先用 4 字节）。
func toIPBytes(addr net.IP) []byte {
	if v4 := addr.To4(); v4 != nil {
		return []byte(v4)
	}
	v6 := addr.To16()
	if v6 == nil {
		return nil
	}
	return []byte(v6)
}
