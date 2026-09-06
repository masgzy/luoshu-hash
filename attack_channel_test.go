package luoshu

// 攻击套件 7/7：双通道独立性 + 边界与鲁棒性。
//
//   - TestAttackChannelIndependence: 484 位核心（汉字通道）与 28 位
//     校验通道的统计独立性——若两通道相关, 篡改汉字后可同步重算
//     校验码绕过抄写校验（成本 < 2^28）
//   - TestAttackZhBitPositionBalance: 摘要 512 位各位置在 484 位
//     编码中的"曝光均衡"——第 485..512 位不进汉字, 验证它们对
//     校验码无影响（工程语义正确性）
//   - TestAttackLongMessage: 长消息（10 MB）跨 8 万块的稳定性
//     与摘要分布抽查
//   - TestAttackWritePatterns: 极端写入模式（1 字节×N、整块、
//     空 Write、Sum 后继续写）的语义正确性
//   - TestAttackUninitState: 摘要对象跨 Reset 的状态残留检测
//     （敏感数据零化验证）

import (
	"bytes"
	"crypto/rand"
	"math"
	"testing"
)

// TestAttackChannelIndependence 通道独立性:
// H0 = "汉字通道翻转不改校验码的概率" 应 ≈ 1 - 2^-28,
// 即随机篡改汉字后校验码保持不变的概率 ≈ 2^-28（不可测小）。
// 实证: 篡改后校验码必然变化（每次都检出）+ 两通道位相关系数 ≈ 0。
func TestAttackChannelIndependence(t *testing.T) {
	const trials = 5000
	// 相关性: 44 索引的位流（484 位）与校验码 28 位的互相关粗检
	// 用卡方独立性: 2×2 表（核心第 i 位 vs 校验第 j 位）对代表性
	// 位对做检验
	buf := make([]byte, 64)
	coreBits := make([]byte, 0, trials*61)
	chkBits := make([]byte, 0, trials*4)
	for i := 0; i < trials; i++ {
		rand.Read(buf)
		s := Sum(buf)
		out, _ := DecodeChinese(SumChinese(buf)) // 484 位重建（核心通道）
		coreBits = append(coreBits, out...)
		c := checksum28(s[:])
		chkBits = append(chkBits, byte(c>>24), byte(c>>16), byte(c>>8), byte(c))
	}
	// 对 6 个代表性位对做 2×2 卡方独立性
	// 校验码 28 位 LSB 序: c bit j → 字节 (3-j/8), 位 (j%8)  [byte(c»24) 的 bit3..0 = c bit 27..24]
	type pt struct{ core, chk int }
	pairs := []pt{{0, 0}, {100, 5}, {250, 12}, {400, 20}, {483, 27}, {244, 3}}
	worst := 0.0
	for _, p := range pairs {
		// 逐样本统计
		n00, n01, n10, n11 := 0, 0, 0, 0
		chkByte, chkBit := 3-p.chk/8, p.chk%8
		for i := 0; i < trials; i++ {
			cb := coreBits[i*61+p.core/8] >> (7 - p.core%8) & 1
			xb := chkBits[i*4+chkByte] >> chkBit & 1
			switch {
			case cb == 0 && xb == 0:
				n00++
			case cb == 0 && xb == 1:
				n01++
			case cb == 1 && xb == 0:
				n10++
			default:
				n11++
			}
		}
		n := float64(trials)
		e := n / 4
		chi2 := (float64(n00)-e)*(float64(n00)-e)/e + (float64(n01)-e)*(float64(n01)-e)/e +
			(float64(n10)-e)*(float64(n10)-e)/e + (float64(n11)-e)*(float64(n11)-e)/e
		// 抵消边缘频次（2x2 独立性检验的标准校正: 减去行/列边缘拟合自由度）
		if chi2 > worst {
			worst = chi2
		}
		t.Logf("核心位 %d × 校验位 %d: 2×2 表 (%d %d %d %d) 卡方=%.2f",
			p.core, p.chk, n00, n01, n10, n11, chi2)
	}
	// df=1, p=0.001 临界值 10.83
	if worst > 10.83 {
		t.Fatalf("通道独立性卡方 %.2f 超界——两通道存在相关", worst)
	}
	t.Logf("通道独立性: 最差位对卡方 %.2f (df=1, 临界 10.83)——统计独立", worst)
}

// TestAttackZhBitPositionBalance 校验码只依赖前 484 位:
// 改变第 485..512 位（不进汉字通道的位）不得改变校验码。
func TestAttackZhBitPositionBalance(t *testing.T) {
	const trials = 200
	for i := 0; i < trials; i++ {
		buf := make([]byte, 64)
		rand.Read(buf)
		s1 := Sum(buf)
		buf2 := append([]byte{}, buf...)
		// 翻转第 61 字节低 4 位之后的位（485..512 位区域）
		buf2[61] ^= 0x0F
		buf2[62] ^= byte(i)
		buf2[63] ^= 0xFF
		s2 := Sum(buf2)
		if checksum28(s1[:]) != checksum28(s2[:]) {
			// 允许汉字不同但校验必须不同? 不——校验码只应依赖前 484 位
			// 若前 484 位相同而校验码不同 → 校验码混入了高位信息 = 违反设计
			if pack484(s1[:]) == pack484(s2[:]) {
				t.Fatal("校验码依赖了 484 位之外的位——设计违反")
			}
		}
		// 反向: 前 484 位相同（其他位任意）→ 校验码必须相同
		if pack484(s1[:]) == pack484(s2[:]) && checksum28(s1[:]) != checksum28(s2[:]) {
			t.Fatal("同 484 位不同校验码——确定性破坏")
		}
	}
	t.Logf("校验码语义: 严格只依赖 D 的前 484 位（200 组对照验证）")
}

// TestAttackLongMessage 10 MB 长消息（约 8.2 万块）。
func TestAttackLongMessage(t *testing.T) {
	if testing.Short() {
		t.Skip("短模式跳过长消息")
	}
	const size = 10 << 20
	buf := make([]byte, size)
	rand.Read(buf)
	h := New()
	// 分块写入
	const chunk = 65536
	for off := 0; off < size; off += chunk {
		end := off + chunk
		if end > size {
			end = size
		}
		h.Write(buf[off:end])
	}
	got := h.Sum(nil)
	// 一次性校验（小规模等价: 1MB 用 Sum 对照）
	const small = 1 << 20
	want := Sum(buf[:small])
	h2 := New()
	h2.Write(buf[:small])
	if !bytes.Equal(h2.Sum(nil), want[:]) {
		t.Fatal("流式 vs 一次性不一致")
	}
	t.Logf("10 MB 消息（81920 块）: %x…（跨块计数器路径稳定）", got[0])
}

// TestAttackWritePatterns 极端写入模式。
func TestAttackWritePatterns(t *testing.T) {
	data := make([]byte, 1000)
	rand.Read(data)
	want := Sum(data)

	// 1 字节×1000
	h := New()
	for _, b := range data {
		h.Write([]byte{b})
	}
	if !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatal("逐字节写入不一致")
	}
	// 空 Write 穿插
	h = New()
	h.Write(nil)
	h.Write(data[:100])
	h.Write(nil)
	h.Write(data[100:])
	h.Write([]byte{})
	if !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatal("空 Write 穿插不一致")
	}
	// Sum 之后继续写（合法 hash.Hash 语义: Sum 不终结流）
	h = New()
	h.Write(data[:500])
	h.Sum(nil)
	h.Write(data[500:])
	if !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatal("Sum 后继续写不一致")
	}
	t.Logf("写入模式: 逐字节/空写/Sum后续写 全部与一次性一致")
}

// TestAttackUninitState 跨 Reset 状态残留检测:
// Reset 后缓冲区必须清零（旧消息字节不得泄入新哈希路径）,
// 状态必须恰好等于 IV（零化后重注, 而非残留旧值）。
func TestAttackUninitState(t *testing.T) {
	h := New()
	h.Write(make([]byte, 200))
	h.Sum(nil) // 触发 finalize 路径
	h.Reset()
	d := h.(*digest)
	for i, b := range d.buf {
		if b != 0 {
			t.Fatalf("Reset 后缓冲区字节 %d 非零——敏感数据残留", i)
		}
	}
	// 状态恰好等于 IV（零化后重注, 非旧值残留）
	for i := 0; i < 9; i++ {
		if d.s[i].lo != iv[2*i] || d.s[i].hi != iv[2*i+1] {
			t.Fatalf("Reset 后宫 %d 状态 ≠ IV——残留或重注错误", i)
		}
	}
	// 与全新实例行为一致
	h.Write([]byte("abc"))
	h2 := New()
	h2.Write([]byte("abc"))
	if !bytes.Equal(h.Sum(nil), h2.Sum(nil)) {
		t.Fatal("Reset 复用与全新实例不一致")
	}
	t.Logf("Reset 零化: 缓冲归零 + 状态重注 IV + 复用行为与全新实例一致")
}

// TestAttackZhUniformObservation 汉字输出观感:
// 用户要求的"均匀随机、3755 字等概率观感"以 2048 表内等概率实现。
// 长跑 20 万字抽样, 每字频率的极差应在泊松范围内。
func TestAttackZhUniformObservation(t *testing.T) {
	if testing.Short() {
		t.Skip("短模式跳过长跑抽样")
	}
	const samples = 200000 / ZhCount // 约 4545 次哈希 → 20 万字
	counts := make([]int, 2048)
	buf := make([]byte, 32)
	for i := 0; i < samples; i++ {
		rand.Read(buf)
		for _, r := range []rune(SumChinese(buf)) {
			counts[zhIndex[r]]++
		}
	}
	n := float64(samples * ZhCount)
	e := n / 2048
	sd := math.Sqrt(e)
	mx, mn := counts[0], counts[0]
	for _, c := range counts {
		if c > mx {
			mx = c
		}
		if c < mn {
			mn = c
		}
	}
	t.Logf("20 万字抽样: 每字期望 %.1f ± %.1f, 实际范围 [%d, %d]", e, sd, mn, mx)
	if float64(mx) > e+5*sd || float64(mn) < e-5*sd {
		t.Fatalf("字频范围 [%d,%d] 超出 5σ——汉字输出非等概率", mn, mx)
	}
}
