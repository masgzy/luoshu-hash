package luoshu

// 攻击套件 6/7：差分缩减轮分析（Chabaud–Joux / RX 风格黑盒探测）。
//
// 攻击者模型: 可调用 compressR 指定任意轮数（1..72）, 注入受控
// 差分, 观察输出差异——寻找"低重量差分传播路径"（差分攻击的燃料）。
//
//   - TestAttackDifferentialDiffusion: 消息 1 bit 差分在
//     r ∈ {1,2,3,4,6,8,12,16,24,36,48,72} 轮后的输出差异重量曲线;
//     完整轮必须达到 B(1152, 1/2)（均值 576, 5σ 界 [533, 619]）
//   - TestAttackDifferentialStateInject: 状态 1 bit 差分注入
//     （更强的攻击者假设, 攻击压缩函数入口）——完整轮同样必须饱和
//   - TestAttackDifferentialComplement: 互补差分（全 1 XOR 差分,
//     SHA-0 互补弱点的探测）不得有异常保持
//   - TestAttackDifferentialLowWeightTail: 输出差异重量的低尾分布——
//     随机函数下 P(重量 < 512) ≈ 2^-6.3, 300 次试验中出现多次
//     极低重量即报警
//
// 注: 本套件是黑盒统计探测, 不是穷尽差分路径搜索（后者对 1152 位
// 状态在计算上不可行——这本身即宽管道设计的意义）。规范 PDF 中
// 如实说明此边界。

import (
	"crypto/rand"
	"math/bits"
	"testing"
)

// diffWeight 压缩一对状态/消息的输出差异重量（1152 位）。
func diffWeight(base, flipped *[9]palace) int {
	w := 0
	for i := 0; i < 9; i++ {
		w += bits.OnesCount64(base[i].lo^flipped[i].lo) + bits.OnesCount64(base[i].hi^flipped[i].hi)
	}
	return w
}

// randState 随机初始状态。
func randState() (st [9]palace) {
	var buf [144]byte
	rand.Read(buf[:])
	for i := 0; i < 9; i++ {
		st[i].hi = uint64(buf[i*16])*0x0101010101010101 | uint64(buf[i*16+1])
		st[i].lo = uint64(buf[i*16+8])<<56 | uint64(buf[i*16+9])<<48
	}
	// 简单充分随机化
	for i := 0; i < 9; i++ {
		var b [16]byte
		rand.Read(b[:])
		st[i].hi = encBE(b[0:8])
		st[i].lo = encBE(b[8:16])
	}
	return
}

func encBE(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// runCompress 从状态 st 压缩消息块 m（r 轮）。
func runCompress(st *[9]palace, m []byte, r int) [9]palace {
	var blk [BlockBytes]byte
	copy(blk[:], m)
	out := *st
	compressR(&out, &blk, 0, false, r)
	return out
}

// TestAttackDifferentialDiffusion 消息差分扩散曲线。
func TestAttackDifferentialDiffusion(t *testing.T) {
	const trials = 200
	var m, m2 [BlockBytes]byte
	rand.Read(m[:])
	m2 = m
	m2[0] ^= 1 << 7 // 消息首 bit 差分

	rounds := []int{1, 2, 3, 4, 6, 8, 12, 16, 24, 36, 48, 72}
	for _, r := range rounds {
		total := 0
		low := 0
		for i := 0; i < trials; i++ {
			st := randState()
			a := runCompress(&st, m[:], r)
			b := runCompress(&st, m2[:], r)
			dw := diffWeight(&a, &b)
			total += dw
			if dw < 512 {
				low++
			}
		}
		mean := float64(total) / trials
		t.Logf("轮数 %2d: 输出差异重量均值 %7.1f / 1152（随机终点 576）", r, mean)
		if r == 72 {
			if mean < 533 || mean > 619 {
				t.Fatalf("完整 72 轮消息差分扩散均值 %.1f 超出 5σ 界 [533,619]", mean)
			}
			// 低尾: B(1152,0.5) 下 P(<512) ≈ Φ(-4.4) ≈ 5.4e-6, 200 次中应 ~0
			if low > 1 {
				t.Fatalf("完整轮出现 %d 次低重量差异（<512/1152）——差分保持路径可疑", low)
			}
		}
	}
	// 扩散单调性 sanity: 4 轮后应已超过 1/4 状态（差分至少进入多宫）
	st := randState()
	a := runCompress(&st, m[:], 4)
	b := runCompress(&st, m2[:], 4)
	if diffWeight(&a, &b) < 288 {
		t.Fatal("4 轮后消息差分扩散 < 288/1152 位——扩散过慢")
	}
}

// TestAttackDifferentialStateInject 状态差分注入（更强攻击者）。
func TestAttackDifferentialStateInject(t *testing.T) {
	const trials = 200
	var m [BlockBytes]byte
	rand.Read(m[:])
	for _, r := range []int{4, 12, 72} {
		total, low := 0, 0
		for i := 0; i < trials; i++ {
			st := randState()
			st2 := st
			st2[0].lo ^= 1 // 状态首 bit 差分
			a := runCompress(&st, m[:], r)
			b := runCompress(&st2, m[:], r)
			dw := diffWeight(&a, &b)
			total += dw
			if dw < 512 {
				low++
			}
		}
		mean := float64(total) / trials
		t.Logf("状态差分/轮数 %2d: 差异重量均值 %7.1f / 1152", r, mean)
		if r == 72 {
			if mean < 533 || mean > 619 {
				t.Fatalf("状态差分 72 轮扩散均值 %.1f 超界", mean)
			}
			if low > 1 {
				t.Fatalf("状态差分完整轮低重量差异 %d 次——可疑", low)
			}
		}
	}
}

// TestAttackDifferentialComplement 互补差分探测（SHA-0 旧疾）。
// 输入对 (x, ~x): 若压缩存在互补性质, 输出差分会有结构性偏置。
func TestAttackDifferentialComplement(t *testing.T) {
	const trials = 200
	total := 0
	for i := 0; i < trials; i++ {
		var m [BlockBytes]byte
		rand.Read(m[:])
		st := randState()
		a := runCompress(&st, m[:], Rounds)
		var m2 [BlockBytes]byte
		for j := range m {
			m2[j] = ^m[j]
		}
		b := runCompress(&st, m2[:], Rounds)
		total += diffWeight(&a, &b)
	}
	mean := float64(total) / trials
	t.Logf("互补输入对差异重量均值 %.1f / 1152（随机 576）", mean)
	if mean < 533 || mean > 619 {
		t.Fatalf("互补差分均值 %.1f 超出 5σ 界——存在互补结构性", mean)
	}
}

// TestAttackDifferentialLowWeightTail 完整轮低重量差分聚集探测:
// 500 次差分试验, 统计 < 460 位的极低重量出现次数（随机下
// P(<460) = Φ(-6.5) ≈ 4e-11, 期望 0）。
func TestAttackDifferentialLowWeightTail(t *testing.T) {
	const trials = 500
	var m, m2 [BlockBytes]byte
	extreme := 0
	minW := 1152
	for i := 0; i < trials; i++ {
		rand.Read(m[:])
		m2 = m
		bit := i % 1024
		m2[bit/8] ^= 1 << (7 - bit%8)
		st := randState()
		a := runCompress(&st, m[:], Rounds)
		b := runCompress(&st, m2[:], Rounds)
		dw := diffWeight(&a, &b)
		if dw < minW {
			minW = dw
		}
		if dw < 460 {
			extreme++
		}
	}
	t.Logf("500 次差分试验: 最小差异重量 %d/1152（随机期望 ~485 = μ-5σ）", minW)
	if extreme > 0 {
		t.Fatalf("出现 %d 次极低重量差异（<460）——差分保持路径存在", extreme)
	}
}
