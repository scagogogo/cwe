package cwe

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ParseCWEID 验证并规范化CWE ID格式
//
// 方法功能:
// 解析、验证并规范化CWE ID字符串，将各种格式的CWE ID转换为标准的"CWE-数字"格式。
// 该方法能处理多种常见的CWE ID格式变体，包括前缀大小写差异、前导零、空格等。
// 处理后的ID会移除前导零并采用标准的"CWE-数字"格式。
//
// 参数:
// - id: string - 要解析的CWE ID字符串，可以是多种格式
//
// 返回值:
// - string: 标准化后的CWE ID，格式为"CWE-数字"(如"CWE-79")
// - error: 如无法解析则返回错误，否则返回nil
//
// 接受的输入格式:
// - 标准格式: "CWE-79"
// - 小写前缀: "cwe-79"
// - 混合大小写: "CwE-79"
// - 带空格: "CWE 79"
// - 前导零: "CWE-079"
// - 纯数字: "79"
//
// 错误处理:
// - 空字符串: 返回"无法解析空的CWE ID"
// - 无法匹配任何有效格式: 返回"无法解析CWE ID"
//
// 使用示例:
// ```go
// // 标准格式
// id1, err := ParseCWEID("CWE-79")
//
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// fmt.Println(id1) // 输出: CWE-79
//
// // 处理前导零
// id2, err := ParseCWEID("CWE-007")
//
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// fmt.Println(id2) // 输出: CWE-7
//
// // 处理纯数字
// id3, err := ParseCWEID("123")
//
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// fmt.Println(id3) // 输出: CWE-123
//
// // 处理不规范格式
// id4, err := ParseCWEID("cwe 456")
//
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// fmt.Println(id4) // 输出: CWE-456
// ```
//
// 边界情况:
// - 非常大的数字ID仍将被接受
// - 极端不规范的格式可能导致解析失败
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
