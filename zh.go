package luoshu

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/bits"
)

const (
	// ZhCount 汉字输出字数（512 位中的低 484 位 = 44 × 11 bit）。
	ZhCount = 44
	// ZhBits 每字携带比特数（log2 2048）。
	ZhBits = 11
	// CheckBits 抄写校验码位数（D 低 484 位的折叠函数, 工程特性）。
	CheckBits = 28
	// CheckHexLen 校验码 hex 字符数。
	CheckHexLen = 7
)

// zhIndex[r]: 汉字 r → 11 位索引；变量声明于 zhchars.go，此处仅初始化。
// zhRunes[i]: 索引 i → 汉字（避免 string 下标访问返回字节而非 rune 的陷阱）。
var zhRunes []rune

func init() {
	zhRunes = []rune(zhTable)
	if len(zhRunes) != 2048 {
		panic("luoshu: 汉字表长度非 2048")
	}
	zhIndex = make(map[rune]uint16, 2048)
	for i, r := range zhRunes {
		if _, dup := zhIndex[r]; dup {
			panic("luoshu: 汉字表有重复字")
		}
		zhIndex[r] = uint16(i)
	}
	// 表指纹自检
	sum := sha256.Sum256([]byte(zhTable))
	if hex.EncodeToString(sum[:]) != zhTableSHA256 {
		panic("luoshu: 汉字表 SHA-256 指纹不匹配")
	}
}

// pack484 从 64 字节摘要中 MSB-first 提取 44 个 11 位索引
// （恰好覆盖 D 的低 484 位，无重叠无遗漏）。
func pack484(d []byte) (idx [ZhCount]uint16) {
	var acc uint64
	accBits, di := 0, 0
	for i := 0; i < ZhCount; i++ {
		for accBits < ZhBits {
			acc = acc<<8 | uint64(d[di])
			di++
			accBits += 8
		}
		idx[i] = uint16(acc>>(accBits-ZhBits)) & 0x7FF
		accBits -= ZhBits
	}
	return
}

// checksum28 计算 28 位抄写校验码（ARX 折叠）：
//
//	c₀ = 0x1BD11BDA
//	c_{i+1} = ROTL32(c_i + idx_i·φ + i, 11)   φ = 0x9E3779B1（黄金比例）
//	c = c₄₄ ⊕ ROTL(c₄₄,13) ⊕ ROTL(c₄₄,19)，取低 28 位
//
// 设计依据（防两类已证伪缺陷）：
//   - 纯线性折叠 + 截断（旧方案一）：每步 & mask 使旋转溢出位被丢弃，
//     前若干字的信息逐轮坍缩，对校验码完全不可见；
//   - 纯线性折叠 + 终局截断（旧方案二）：字 i 的注入位经 11·(44−i) mod 32
//     次旋转后，部分位置(i=18,21,24,27,30…)的低位恰好落入 bit 28–31
//     被截断丢弃——ROTL 是双射, 但截断砍掉了 4 个可见通道。
//
// 现方案用 ARX（模加进位链非线性 + 位置盐 i 防换位等价 + 乘黄金比例
// 扩散 11 位输入到全 32 位），终局混合 c⊕ROTL(c,13)⊕ROTL(c,19) 的映射
// 多项式 1+x¹³+x¹⁹ 与 x³²+1=(x+1)³² 互素（三项式在 x=1 处值为 1），
// 故为 GF(2) 双射且核为零：任意 32 位非零差异映射后仍非零,
// 且每个差异位的三重影像 {b, b+13, b+19} (mod 32) 至少一个落在低 28 位,
// 高 4 位信息无损折回。
//
// 仅用于汉字抄写检错（随机差异漏检率 2⁻²⁸，单字替换/换位检出
// 由全位置单元测试机器断言），属工程特性，不构成额外密码学安全层。
func checksum28(d []byte) uint32 {
	idx := pack484(d)
	c := uint32(0x1BD11BDA)
	for i, v := range idx {
		c = bits.RotateLeft32(c+uint32(v)*0x9E3779B1+uint32(i), 11)
	}
	c ^= bits.RotateLeft32(c, 13) ^ bits.RotateLeft32(c, 19)
	return c & ((1 << CheckBits) - 1)
}

// SumHex 返回 data 的十六进制摘要（128 字符，完整 512 位）。
func SumHex(data []byte) string {
	s := Sum(data)
	return hex.EncodeToString(s[:])
}

// SumChinese 返回 data 的 44 汉字摘要（D 低 484 位 → 2048 字表双射）。
func SumChinese(data []byte) string {
	s := Sum(data)
	idx := pack484(s[:])
	runes := make([]rune, ZhCount)
	for i, v := range idx {
		runes[i] = zhRunes[v]
	}
	return string(runes)
}

// checkHexOf 把 28 位校验码转为 7 个 hex 字符。
func checkHexOf(c uint32) string {
	return hex.EncodeToString([]byte{byte(c >> 20), byte(c >> 12), byte(c >> 4), byte(c << 4)})[0:CheckHexLen]
}

// ChecksumHex 返回 28 位抄写校验码的 7 个 hex 字符。
func ChecksumHex(data []byte) string {
	s := Sum(data)
	return checkHexOf(checksum28(s[:]))
}

// DecodeChinese 将 44 汉字无损解码为 484 位（61 字节，MSB-first）。
// 字表外的汉字返回错误。
func DecodeChinese(s string) (out []byte, err error) {
	runes := []rune(s)
	if len(runes) != ZhCount {
		return nil, errors.New("luoshu: 汉字摘要长度必须为 44 字")
	}
	out = make([]byte, 61)
	var acc uint64
	accBits, oi := 0, 0
	for _, r := range runes {
		v, ok := zhIndex[r]
		if !ok {
			return nil, errors.New("luoshu: 汉字不在洛书 2048 字表内: " + string(r))
		}
		acc = acc<<ZhBits | uint64(v)
		accBits += ZhBits
		for accBits >= 8 && oi < 61 {
			out[oi] = byte(acc >> (accBits - 8))
			oi++
			accBits -= 8
		}
	}
	// 484 = 60×8 + 4: 残余 4 位写入第 61 字节高位, 保证 pack484(out)
	// 与 pack484(完整摘要) 提取出完全相同的 44 个索引（校验一致的前提）。
	if accBits > 0 && oi < 61 {
		out[oi] = byte(acc << (8 - accBits))
	}
	return out, nil
}

// VerifyChinese 校验"44 汉字 + 7 位校验 hex"的抄写一致性。
// 返回 nil 表示校验通过。仅检抄写错误，非安全验证。
func VerifyChinese(zh, checkHex string) error {
	out, err := DecodeChinese(zh)
	if err != nil {
		return err
	}
	if len(checkHex) != CheckHexLen {
		return errors.New("luoshu: 校验码长度必须为 7 个 hex 字符")
	}
	c := checksum28(out)
	want := checkHexOf(c)
	if want != checkHex {
		return errors.New("luoshu: 校验不一致，抄写可能有误（期望 " + want + "）")
	}
	return nil
}
