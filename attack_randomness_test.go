package luoshu

// 攻击套件 2/7：输出随机性统计检验。
//
//   - TestAttackBitFrequency: 512 个输出位的位频率卡方（大样本）
//   - TestAttackZhDistribution: 2048 字表上的字分布卡方（均匀双射的实证）
//   - TestAttackRunsTest: 游程检验（位流中同值连续段 vs 理论期望）
//   - TestAttackMaxRun: 最大游程长度界（随机流中 ~log2(n)+1）
//
// 均匀随机输出是"484 位核心经 44×11 双射映射后等概率出现 2048 字"
// 的前提：若某些位或某些字统计偏置, 双射的表观均匀性即被破坏。

import (
	"crypto/rand"
	"math"
	"testing"
)

// collectBits 收集 totalBits 个输出位（来自随机输入的摘要）。
func collectBits(t *testing.T, totalBits int) []byte {
	out := make([]byte, 0, totalBits/8+8)
	buf := make([]byte, 64)
	nBytes := totalBits/8 + 1
	for len(out) < nBytes {
		rand.Read(buf)
		s := Sum(buf)
		out = append(out, s[:]...)
	}
	return out
}

// TestAttackBitFrequency 位频率卡方：每位 1 的次数 vs n/2。
func TestAttackBitFrequency(t *testing.T) {
	const samples = 3000 // 3000×512 = 1,536,000 位
	ones := [512]int{}
	buf := make([]byte, 64)
	for s := 0; s < samples; s++ {
		rand.Read(buf)
		d := Sum(buf)
		for i := 0; i < 64; i++ {
			v := d[i]
			for j := 0; j < 8; j++ {
				ones[i*8+j] += int(v >> (7 - j) & 1)
			}
		}
	}
	// 每位 z 分数与全位合并卡方
	n := float64(samples)
	chi2 := 0.0
	worst := 0.0
	worstBit := 0
	for bit, o := range ones {
		e := n / 2
		chi2 += (float64(o) - e) * (float64(o) - e) / e * 2 // 两格(0/1)各贡献
		z := (float64(o) - e) / math.Sqrt(n) / 0.5
		if z > worst {
			worst, worstBit = z, bit
		}
	}
	t.Logf("位频卡方 = %.1f (df=511, 临界值 610 @ p=0.001); 最大偏离位 %d z=%.2fσ", chi2, worstBit, worst)
	if chi2 > 610 {
		t.Fatalf("位频率卡方 %.1f 超出 df=511 的 p=0.001 临界值 610", chi2)
	}
	if worst > 4.5 {
		t.Fatalf("位 %d 频率偏离 %.2fσ, 超出 4.5σ", worstBit, worst)
	}
}

// TestAttackZhDistribution 字分布卡方：44 字 × 样本数 → 2048 桶。
func TestAttackZhDistribution(t *testing.T) {
	const samples = 24000 // 24000×44 = 1,056,000 字 → 每桶期望 ~516
	counts := make([]int, 2048)
	buf := make([]byte, 64)
	for s := 0; s < samples; s++ {
		rand.Read(buf)
		zh := SumChinese(buf)
		for _, r := range []rune(zh) {
			counts[zhIndex[r]]++
		}
	}
	n := float64(samples * ZhCount)
	e := n / 2048
	chi2 := 0.0
	for _, c := range counts {
		chi2 += (float64(c) - e) * (float64(c) - e) / e
	}
	t.Logf("字分布卡方 = %.1f (df=2047, 临界值 2264 @ p=0.001)", chi2)
	if chi2 > 2264 {
		t.Fatalf("2048 字分布卡方 %.1f 超出 p=0.001 临界值", chi2)
	}
}

// TestAttackRunsTest 游程检验（NIST SP 800-22 风格）。
// 随机位流中长度 k 的游程出现概率: n/2^(k+2)（k≥1, 大 n）。
func TestAttackRunsTest(t *testing.T) {
	bits := collectBits(t, 4_000_000) // 400 万位
	n := len(bits) * 8
	// 统计游程（按位扫描, 用位运算）
	runs := [26]int{}
	prev := bits[0] >> 7 & 1
	curLen := 1
	for i := 1; i < n; i++ {
		b := bits[i/8] >> (7 - i%8) & 1
		if b == prev {
			curLen++
		} else {
			if curLen < 25 {
				runs[curLen]++
			} else {
				runs[25]++
			}
			curLen = 1
			prev = b
		}
	}
	// 期望: E[run k] ≈ n / 2^(k+1)（同值游程含 0/1 两类）
	chi2 := 0.0
	df := 0
	for k := 1; k <= 20; k++ {
		exp := float64(n) / float64(int(1)<<(k+1))
		if exp < 5 {
			break
		}
		chi2 += (float64(runs[k]) - exp) * (float64(runs[k]) - exp) / exp
		df++
	}
	t.Logf("游程检验卡方 = %.1f (df=%d, 临界值 %.1f @ p=0.001)", chi2, df, chi2Crit(df))
	if chi2 > chi2Crit(df) {
		t.Fatalf("游程分布卡方 %.1f 超出 p=0.001 临界值 (df=%d)", chi2, df)
	}
}

// TestAttackMaxRun 最大游程不得超界: n=4×10^6 位随机流的最大游程
// 期望约 log2(n) ≈ 22, 容忍到 34。
func TestAttackMaxRun(t *testing.T) {
	bits := collectBits(t, 4_000_000)
	maxRun, cur := 0, 0
	var prev byte
	for i := 0; i < len(bits)*8; i++ {
		b := bits[i/8] >> (7 - i%8) & 1
		if i == 0 || b != prev {
			cur = 1
			prev = b
		} else {
			cur++
		}
		if cur > maxRun {
			maxRun = cur
		}
	}
	t.Logf("4M 位流最大游程 = %d (界 34, 期望 ~22)", maxRun)
	if maxRun > 34 {
		t.Fatalf("最大游程 %d 超界（n=4M 随机流不应超过 34）", maxRun)
	}
}

// chi2Crit p=0.001 的卡方临界值（Wilson-Hilferty 近似, df≥8 误差 <1%）。
func chi2Crit(df int) float64 {
	if df < 1 {
		df = 1
	}
	// p=0.001 → z = 3.0902
	z := 3.0902
	return float64(df) * math.Pow(1-2/(9*float64(df))+z*math.Sqrt(2/(9*float64(df))), 3)
}
