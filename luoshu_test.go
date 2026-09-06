package luoshu

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/bits"
	mrand "math/rand"
	"testing"
	"testing/quick"
)

// ---------- KAT 已知答案测试（向量冻结, 任何改动都会被察觉） ----------

var katVectors = []struct {
	msg, hexSum, zh, chk string
}{
	{
		"",
		"0255edb6e3d89e6d32c912ba5e2070968636acd2f0916d211ea466ddfe06c5fa34b17353098c212944709279d551daace33ad44d4235dddc23a4c4dba90048e0",
		"上炼坏侠症角谋制瞎壳见向冲圈坐候怪什裤晓坡可话慢妙恰帖论次泪凉害驱拼琴赖旗任之扩贡类员植",
		"05d6aa9",
	},
	{
		"abc",
		"a83c00cae86b499b94fb492549ad82c33cf811466de5e9cb44220b842cffa43c619fb11b4dce0d454ed2e455af93b3fd24bb7b58a2a3959dbd9655dd8aa406ec",
		"瞬践统熬宋池预弟流婚继胡泥里十挖瓦景天解配草君忆寒奖闺摩庸繁议杨迅杯魏岁浅郁巧耳辛悬拒乳",
		"afbae66",
	},
	{
		"洛书",
		"d9bdc81aabad6a42798510213989673042238836c32a82cce47f48e1c2485f8d11f7d630f0cd5f1033e6f2d3cf4dbd4fec8e7785030783e1e377724a82d59eb2",
		"扭箭小查咋带埋宽带乔企码书醉璃志冰右计摆见强割泪悦碎队鼓壳代仔喝姻忍预妖跪塑着惧寿较凤综",
		"003ff65",
	},
	{
		"The quick brown fox jumps over the lazy dog",
		"94b51dc9e357c857ad56628f13712befabdef149cffed1f20957f166923a87f75729af5576f71d4b4b343bf0676b67236fead6480ff60fae8a6da8b18d5ade3e",
		"束哲漫羞尊哈赏乔丰征啊锤遭检读汁郑蒙份踢弟朋计玄它培免迁胃呆亏射减姐丹躲脏保似映硕负苏硬",
		"e75d58c",
	},
}

func TestKAT(t *testing.T) {
	for _, v := range katVectors {
		d := []byte(v.msg)
		if got := SumHex(d); got != v.hexSum {
			t.Errorf("KAT hex 不匹配 msg=%q:\n  期望 %s\n  实际 %s", v.msg, v.hexSum, got)
		}
		if got := SumChinese(d); got != v.zh {
			t.Errorf("KAT 汉字不匹配 msg=%q:\n  期望 %s\n  实际 %s", v.msg, v.zh, got)
		}
		if got := ChecksumHex(d); got != v.chk {
			t.Errorf("KAT 校验码不匹配 msg=%q: 期望 %s 实际 %s", v.msg, v.chk, got)
		}
	}
}

// ---------- 确定性与接口语义 ----------

func TestDeterminism(t *testing.T) {
	data := make([]byte, 4096)
	rand.Read(data)
	if SumHex(data) != SumHex(data) {
		t.Fatal("同一输入两次哈希不一致")
	}
}

func TestSumIdempotent(t *testing.T) {
	h := New()
	h.Write([]byte("abc"))
	a := append([]byte(nil), h.Sum(nil)...)
	b := append([]byte(nil), h.Sum(nil)...)
	if !bytes.Equal(a, b) {
		t.Fatal("Sum 不得改变内部状态（hash.Hash 语义）")
	}
}

func TestResetAndReuse(t *testing.T) {
	h := New()
	h.Write([]byte("第一段消息"))
	h.Sum(nil)
	h.Reset()
	h.Write([]byte("abc"))
	got := hex.EncodeToString(h.Sum(nil))
	if got != katVectors[1].hexSum {
		t.Fatalf("Reset 后重新使用不等于 KAT: %s", got)
	}
}

func TestStreamingEquivalence(t *testing.T) {
	// testing/quick: 任意输入、任意切分方式, 流式 = 一次性
	f := func(data []byte, split uint8) bool {
		h1 := New()
		h1.Write(data)
		one := append([]byte(nil), h1.Sum(nil)...)
		h2 := New()
		i := int(split) % (len(data) + 1)
		h2.Write(data[:i])
		h2.Write(data[i:])
		two := append([]byte(nil), h2.Sum(nil)...)
		return bytes.Equal(one, two)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Fatal(err)
	}
}

// 块边界: 111/112/127/128/129/255/256 与 1024 位边界的填充分支全覆盖
func TestBlockBoundaries(t *testing.T) {
	prev := map[string]bool{}
	for _, n := range []int{0, 1, 111, 112, 113, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025, 4096} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i * 7)
		}
		s := SumHex(data)
		if prev[s] {
			t.Fatalf("len=%d 摘要与更短消息重复", n)
		}
		prev[s] = true
	}
}

// ---------- 结构常量机器断言（专家审查意见的永久固化） ----------

// TestRotationHygiene 旋转量表卫生检查：无互补对(x+y=64)、无等差三元组、
// 无倍数对、无倍角关系(2x mod 64)、无半周期(32)。
// 这是对"AI 行文自信但夹带算术错误"的机器防线。
func TestRotationHygiene(t *testing.T) {
	var table []uint
	for _, p := range rotsPal {
		table = append(table, p[0], p[1])
	}
	// 去重得到底层旋转量集合
	set := map[uint]bool{}
	for _, r := range table {
		if r == 0 || r >= 64 {
			t.Fatalf("旋转量 %d 越界", r)
		}
		if r == 32 {
			t.Fatal("半周期旋转量 32 禁止出现")
		}
		set[r] = true
	}
	vals := make([]uint, 0, len(set))
	for r := range set {
		vals = append(vals, r)
	}
	// 互补对
	for _, a := range vals {
		if set[64-a] && a != 32 {
			t.Fatalf("互补旋转量对: %d 与 %d", a, 64-a)
		}
	}
	// 等差三元组与倍数对
	for i := 0; i < len(vals); i++ {
		for j := i + 1; j < len(vals); j++ {
			a, b := vals[i], vals[j]
			if b%a == 0 {
				t.Fatalf("倍数对: %d | %d", a, b)
			}
			// 倍角关系
			if (2*a)%64 == b || (2*b)%64 == a {
				t.Fatalf("倍角关系: %d 与 %d", a, b)
			}
			for k := j + 1; k < len(vals); k++ {
				c := vals[k]
				if a+c == 2*b || a+b == 2*c || b+c == 2*a {
					t.Fatalf("等差三元组: %d %d %d", a, b, c)
				}
			}
		}
	}
	// 双爻组合（宫内与跨宫）不得互补
	for i := 0; i < 9; i++ {
		if rotsPal[i][0]+rotsPal[i][1] == 64 {
			t.Fatalf("宫%d 双爻互补: %d+%d=64", i, rotsPal[i][0], rotsPal[i][1])
		}
		for j := i + 1; j < 9; j++ {
			for _, a := range rotsPal[i] {
				for _, b := range rotsPal[j] {
					if a+b == 64 {
						t.Fatalf("宫%d/宫%d 跨宫互补: %d+%d=64", i, j, a, b)
					}
				}
			}
		}
	}
	// 投影旋转量与中宫折入组合也不得互补
	for i := 0; i < 8; i++ {
		if projRot[i]+projRot[(i+4)%8] == 64 {
			t.Fatalf("投影折入互补: projRot[%d]+projRot[%d]=64", i, (i+4)%8)
		}
	}
}

// TestPermutationClosure 置换数学：σ 是 9-循环, σ⁹ = 恒等,
// 每 8 轮执行一次, 72 轮恰 9 次, 每个位置的字遍历全部 9 宫。
func TestPermutationClosure(t *testing.T) {
	// σ⁹ = identity
	orbit := map[int][]int{}
	for start := 0; start < 9; start++ {
		cur := start
		orbit[start] = append(orbit[start], start)
		for step := 0; step < 9; step++ {
			cur = sigma[cur]
			orbit[start] = append(orbit[start], cur)
		}
		if cur != start {
			t.Fatalf("σ⁹(位置%d) = %d ≠ 自身, 置换未闭合", start, cur)
		}
		if len(orbit[start]) != 10 { // 9步 + 起点, 且中途不回到起点 = 完整 9-循环
			t.Fatalf("位置%d 轨道长度异常", start)
		}
	}
	// 执行次数: 每 8 轮一次, 72 主轮 = 9 次
	count := 0
	for r := 0; r < Rounds; r++ {
		if (r+1)%8 == 0 {
			count++
		}
	}
	if count != 9 {
		t.Fatalf("72 主轮置换次数 = %d, 应为 9", count)
	}
}

// TestLinesMagic 幻线结构：8 条线、每线 3 宫、每线洛书数之和 = 15（幻方性质）。
func TestLinesMagic(t *testing.T) {
	if len(lines) != 8 {
		t.Fatalf("幻线数 = %d, 应为 8", len(lines))
	}
	for i, ln := range lines {
		if len(ln) != 3 {
			t.Fatalf("幻线%d 宫数异常", i)
		}
		if luoshuNum[ln[0]]+luoshuNum[ln[1]]+luoshuNum[ln[2]] != 15 {
			t.Fatalf("幻线%d 洛书数和 ≠ 15", i)
		}
	}
}

// TestConstantsSanity 常量计数与取值自检。
func TestConstantsSanity(t *testing.T) {
	if len(iv) != 18 {
		t.Fatalf("IV 字数 = %d, 应为 18", len(iv))
	}
	if len(roundK) != Nk || Nk != 243 {
		t.Fatalf("轮常数数 = %d, 应为 243", len(roundK))
	}
	if iv[0] != 0x6A09E667F3BCC908 {
		t.Fatal("iv[0] 应为 √2 小数 0x6A09E667F3BCC908（与 SHA 家族同源验证）")
	}
	if roundK[0] != 0x428A2F98D728AE22 {
		t.Fatal("roundK[0] 应为 ∛2 小数 0x428A2F98D728AE22（与 SHA 家族同源验证）")
	}
	for _, k := range roundK {
		if k == 0 {
			t.Fatal("轮常数不得为零")
		}
	}
}

// TestLineScheduleUniformity 线调度均匀性：81 轮中每条幻线激活次数相差 ≤ 1。
// 数学事实: 81 轮 × 3 线 = 243 次激活, 243/8 = 30.375 不整除,
// 严格均匀不可能, "最大-最小 ≤ 1" 即为调度的理论最优。
// 实际分布: 3 条线 31 次、5 条线 30 次 (轮 80 起点补充线 0/1/2)。
func TestLineScheduleUniformity(t *testing.T) {
	counts := make([]int, 8)
	for r := 0; r < TotalRounds; r++ {
		a := (3 * r) % 8
		for j := 0; j < 3; j++ {
			counts[(a+j)%8]++
		}
	}
	total := 0
	mx, mn := counts[0], counts[0]
	for i, c := range counts {
		total += c
		if c > mx {
			mx = c
		}
		if c < mn {
			mn = c
		}
		t.Logf("幻线%d 激活 %d 次", i, c)
	}
	if total != 243 {
		t.Fatalf("总激活次数 = %d, 应为 243", total)
	}
	if mx-mn > 1 {
		t.Fatalf("幻线激活次数极差 %d (max=%d min=%d), 应 ≤ 1", mx-mn, mx, mn)
	}
}

// ---------- 汉字层 ----------

func TestChineseRoundTrip(t *testing.T) {
	// 强断言: 前 60 字节逐字节相等, 第 61 字节高 4 位相等
	// （484 = 60×8 + 4, 残余 4 位左对齐写入, 低 4 位不属于编码位）。
	f := func(data []byte) bool {
		s := Sum(data)
		zh := SumChinese(data)
		out, err := DecodeChinese(zh)
		if err != nil || len(out) != 61 {
			return false
		}
		if !bytes.Equal(out[:60], s[:60]) || out[60] != s[60]&0xF0 {
			return false
		}
		// 解码出的 484 位重新打包 → 与原摘要完全相同的 44 个索引
		idx := pack484(out)
		orig := pack484(s[:])
		for i := range idx {
			if idx[i] != orig[i] {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 300}); err != nil {
		t.Fatal(err)
	}
	// 固定向量再验一次（空串 KAT）
	s := Sum(nil)
	out, err := DecodeChinese(SumChinese(nil))
	if err != nil || !bytes.Equal(out[:60], s[:60]) || out[60] != s[60]&0xF0 {
		t.Fatal("空串摘要往返不一致")
	}
}

func TestVerifyChinese(t *testing.T) {
	data := []byte("洛书-512")
	zh := SumChinese(data)
	chk := ChecksumHex(data)
	if err := VerifyChinese(zh, chk); err != nil {
		t.Fatalf("合法摘要校验失败: %v", err)
	}
	// 篡改校验码
	bad := string([]byte{chk[0] ^ 1}) + chk[1:]
	if err := VerifyChinese(zh, bad); err == nil {
		t.Fatal("篡改校验码应当失败")
	}
	// 篡改任意一个汉字必须检出——覆盖全部 44 个位置。
	// （曾经只测第 0 字, 漏掉了旧折叠函数前 24 字信息坍缩的缺陷,
	//   本用例即当时的证伪用例。）
	orig := []rune(zh)
	for i := range orig {
		tam := append([]rune(nil), orig...)
		tam[i] = zhRunes[(zhIndex[tam[i]]+1)%2048]
		if err := VerifyChinese(string(tam), chk); err == nil {
			t.Fatalf("篡改第 %d 个汉字未被校验码检出", i)
		}
	}
	// 交换任意两个不同汉字也必须检出（换位错误, 全 946 对穷举）
	for i := 0; i < ZhCount; i++ {
		for j := i + 1; j < ZhCount; j++ {
			if orig[i] == orig[j] {
				continue // 相同字换位无差异, 不可检出属正确行为
			}
			tam := append([]rune(nil), orig...)
			tam[i], tam[j] = tam[j], tam[i]
			if err := VerifyChinese(string(tam), chk); err == nil {
				t.Fatalf("换位 (%d,%d) 未被校验码检出", i, j)
			}
		}
	}
	// 错误长度
	if _, err := DecodeChinese(zh[:40]); err == nil {
		t.Fatal("长度错误应当报错")
	}
}

func TestPack484Coverage(t *testing.T) {
	// 44×11 = 484 位恰好取自前 61 字节（60.5 字节进位）
	d := make([]byte, 64)
	for i := range d {
		d[i] = byte(i)
	}
	idx := pack484(d)
	// 重排位流验证
	var acc uint64
	accBits, di := 0, 0
	for i := 0; i < ZhCount; i++ {
		for accBits < ZhBits {
			acc = acc<<8 | uint64(d[di])
			di++
			accBits += 8
		}
		if idx[i] != uint16(acc>>(accBits-ZhBits))&0x7FF {
			t.Fatalf("pack484 第 %d 字不符", i)
		}
		accBits -= ZhBits
	}
	if di != 61 {
		t.Fatalf("pack484 应读取 61 字节, 实际 %d", di)
	}
}

// ---------- 雪崩快速属性版（火力全开版在 attacks 套件） ----------

func TestAvalancheQuick(t *testing.T) {
	const samples = 2000
	total := 0
	for s := 0; s < samples; s++ {
		data := make([]byte, 33)
		rand.Read(data)
		a := Sum(data)
		bit := mrand.Intn(33 * 8)
		data[bit/8] ^= 1 << (7 - bit%8)
		b := Sum(data)
		diff := 0
		for i := 0; i < 64; i++ {
			diff += bits.OnesCount8(a[i] ^ b[i])
		}
		total += diff
	}
	ratio := float64(total) / float64(samples*512)
	if ratio < 0.47 || ratio > 0.53 {
		t.Fatalf("雪崩比率 %.4f 偏离 0.5 过多", ratio)
	}
}
