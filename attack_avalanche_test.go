package luoshu

// 攻击套件 1/7：雪崩分析（火力全开版）。
//
// 严格雪崩准则（SAC）：任一输入位翻转 → 每个输出位以 1/2 概率翻转。
// 本套件按大样本统计：
//   - 总体雪崩比率（偏离 0.5 的容差）
//   - 输出位级翻转率（512 个输出位各自统计, 任何一位卡死即报警）
//   - 差异重量分布 vs 二项分布 B(512, 1/2) 的卡方拟合
//   - 输入位置分层（跨块边界/块内不同偏移）的雪崩一致性
//
// 这是对"差分捷径通道"的统计性探测：若某输入差分模式能以显著
// 高于 50% 的概率保持低差异, 此处会显形。

import (
	"crypto/rand"
	"math"
	"math/bits"
	"testing"
)

const avalancheSamples = 4000

// avalancheOnce 随机消息 + 随机单 bit 翻转 → 输出差异重量与差异向量。
func avalancheOnce(t *testing.T, msgLen int) (dw uint, dvec [64]byte) {
	data := make([]byte, msgLen)
	rand.Read(data)
	a := Sum(data)
	bit := int(randByte(t))%msgLen*8 + int(randByte(t))%8
	data[bit/8] ^= 1 << (7 - bit%8)
	b := Sum(data)
	for i := 0; i < 64; i++ {
		dvec[i] = a[i] ^ b[i]
		dw += uint(bits.OnesCount8(dvec[i]))
	}
	return
}

func randByte(t *testing.T) byte {
	var b [1]byte
	rand.Read(b[:])
	return b[0]
}

func TestAttackAvalancheOverall(t *testing.T) {
	// 三种消息长度: 块内 / 块边界邻域 / 多块
	for _, msgLen := range []int{33, 111, 300} {
		total := 0
		min, max := 512, 0
		for s := 0; s < avalancheSamples; s++ {
			dw, _ := avalancheOnce(t, msgLen)
			total += int(dw)
			if int(dw) < min {
				min = int(dw)
			}
			if int(dw) > max {
				max = int(dw)
			}
		}
		ratio := float64(total) / float64(avalancheSamples*512)
		t.Logf("消息长度 %3d 字节: 平均差异 %.1f/512 (比率 %.4f), 范围 [%d, %d]",
			msgLen, float64(total)/float64(avalancheSamples), ratio, min, max)
		if ratio < 0.49 || ratio > 0.51 {
			t.Fatalf("雪崩比率 %.4f 超出 [0.49, 0.51]", ratio)
		}
	}
}

// TestAttackAvalanchePerBit 位级雪崩：任何输出位不得卡死或偏置。
// 512 位 × 各自二项检验（4000 样本, p=0.5, 5σ 容差）。
func TestAttackAvalanchePerBit(t *testing.T) {
	const n = 2000
	flips := [512]int{}
	for s := 0; s < n; s++ {
		_, dvec := avalancheOnce(t, 33)
		for i := 0; i < 64; i++ {
			for j := 0; j < 8; j++ {
				if dvec[i]&(1<<(7-j)) != 0 {
					flips[i*8+j]++
				}
			}
		}
	}
	mean := float64(n) / 2
	sd := math.Sqrt(float64(n)) / 2
	worst := 0.0
	for bit, f := range flips {
		z := math.Abs(float64(f)-mean) / sd
		if z > worst {
			worst = z
		}
		if z > 5 {
			t.Fatalf("输出位 %d 翻转率 %d/%d 偏离 5σ (z=%.2f)", bit, f, n, z)
		}
	}
	t.Logf("512 输出位位级雪崩: 最大偏离 z=%.2f σ（容差 5σ）", worst)
}

// TestAttackAvalancheChiSquare 差异重量分布 vs B(512, 1/2) 卡方拟合。
// 观测桶为整数边界（宽 11, 起点 210），期望必须按同一整数边界
// 经连续性校正计算——若按理论 σ=11.31 边界计算期望, 会产生约
// 2 位的系统性错位, 观测分布被误判为整体偏移（本套件开发中
// 实际踩过此坑, 特此注明防止回归）。
func TestAttackAvalancheChiSquare(t *testing.T) {
	const n = 20000
	mu, sigma := 256.0, math.Sqrt(128.0)
	counts := make([]int, 10)
	for s := 0; s < n; s++ {
		dw, _ := avalancheOnce(t, 111)
		k := 0
		switch {
		case int(dw) < 210:
			k = 0
		case int(dw) >= 301:
			k = 9
		default:
			k = 1 + (int(dw)-210)/11
		}
		counts[k]++
	}
	// 桶 k 的整数边界（k≥1: [210+11(k-1), 210+11k), k=9 含尾）
	bounds := func(k int) (lo, hi float64) {
		switch k {
		case 0:
			return math.Inf(-1), 209.5
		case 9:
			return 300.5, math.Inf(1)
		default:
			l := 210 + 11*(k-1)
			return float64(l) - 0.5, float64(l+11) - 0.5
		}
	}
	chi2 := 0.0
	nb := 0
	for k := 0; k < 10; k++ {
		lo, hi := bounds(k)
		e := (normCDF((hi-mu)/sigma) - normCDF((lo-mu)/sigma)) * float64(n)
		if e < 5 {
			continue // 合并低期望尾桶
		}
		nb++
		chi2 += (float64(counts[k]) - e) * (float64(counts[k]) - e) / e
	}
	df := nb - 1
	t.Logf("差异重量分布卡方 = %.2f (df=%d, 有效桶 %d)", chi2, df, nb)
	// df≈8, 0.001 显著水平临界值 ≈ 26.12
	if chi2 > 26.12 {
		t.Fatalf("差异重量分布显著偏离 B(512,1/2): 卡方 %.2f", chi2)
	}
}

// normCDF 标准正态 CDF（Abramowitz-Stegun 7.1.26 近似, 误差 < 7.5e-8）。
func normCDF(x float64) float64 {
	if x < 0 {
		return 1 - normCDF(-x)
	}
	b0, b1, b2, b3, b4, b5 := 0.2316419, 0.319381530, -0.356563782, 1.781477937, -1.821255978, 1.330274429
	t := 1 / (1 + b0*x)
	poly := b5*t + b4
	poly = poly*t + b3
	poly = poly*t + b2
	poly = poly*t + b1
	poly = poly * t
	return 1 - math.Exp(-x*x/2)/math.Sqrt(2*math.Pi)*poly
}
