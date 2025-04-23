// Package cwe 的工具函数
package cwe

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ParseCWEID 验证并规范化CWE ID格式
func ParseCWEID(id string) (string, error) {
	// 移除空格
	id = strings.TrimSpace(id)

	// 空字符串检查
	if id == "" {
		return "", errors.New("无法解析空的CWE ID")
	}

	// 检查是否已经是正确格式：CWE-数字
	if match, _ := regexp.MatchString(`^CWE-\d+$`, id); match {
		// 提取数字部分并移除前导零
		re := regexp.MustCompile(`^CWE-0*(\d+)$`)
		matches := re.FindStringSubmatch(id)
		if len(matches) >= 2 {
			return fmt.Sprintf("CWE-%s", matches[1]), nil
		}
		return id, nil
	}

	// 检查小写的cwe前缀
	if match, _ := regexp.MatchString(`^[cC][wW][eE]-\d+$`, id); match {
		re := regexp.MustCompile(`^[cC][wW][eE]-0*(\d+)$`)
		matches := re.FindStringSubmatch(id)
		if len(matches) >= 2 {
			return fmt.Sprintf("CWE-%s", matches[1]), nil
		}
	}

	// 检查带空格的格式：CWE 数字
	if match, _ := regexp.MatchString(`^[cC][wW][eE]\s+\d+$`, id); match {
		re := regexp.MustCompile(`^[cC][wW][eE]\s+0*(\d+)$`)
		matches := re.FindStringSubmatch(id)
		if len(matches) >= 2 {
			return fmt.Sprintf("CWE-%s", matches[1]), nil
		}
	}

	// 检查其他格式：CWE-空格-数字
	if match, _ := regexp.MatchString(`^[cC][wW][eE]-\s*\d+$`, id); match {
		re := regexp.MustCompile(`^[cC][wW][eE]-\s*0*(\d+)$`)
		matches := re.FindStringSubmatch(id)
		if len(matches) >= 2 {
			return fmt.Sprintf("CWE-%s", matches[1]), nil
		}
	}

	// 尝试提取纯数字 - 仅接受连续的数字
	re := regexp.MustCompile(`^0*(\d+)$`)
	matches := re.FindStringSubmatch(id)
	if len(matches) >= 2 {
		return fmt.Sprintf("CWE-%s", matches[1]), nil
	}

	// 上述模式都不匹配，则返回错误
	return "", errors.New("无法解析CWE ID")
}
