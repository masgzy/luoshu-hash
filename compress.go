package luoshu

import (
	"encoding/binary"
	"math/bits"
)

// palace 是一个 128 位"宫"，由阴阳双爻（两个 64 位字）构成。
// 模加通过 bits.Add64 进位链跨爻传播，构成真正的 128 位算术。
type palace struct {
	lo, hi uint64
}

const (
	// BlockBytes 分组字节数（1024 位）。
	BlockBytes = 128
	// Rounds 主轮数（8 幻线 × 9 圈 = 72, 每 8 轮做一次位置置换）。
	Rounds = 72
	// FinalRounds 常数收尾轮数（终局注入长度 + 域常数）。
	FinalRounds = 9
	// TotalRounds 总轮数 81。
	TotalRounds = Rounds + FinalRounds
	// MsgWords 消息扩展字数 = 72 轮 × 每轮 6 字（3 线 G × 2 字）。
	MsgWords = 432
	// Nk 轮常数总数 = 81 轮 × 3 线。
	Nk = 243
)

// domK 域分离常数，ASCII "LUOSHU51"。
const domK uint64 = 0x4C554F5348553531

// lastMark 终局标志位（注入中宫高爻最高位）。
const lastMark uint64 = 1 << 63

// sig0/sig1 消息扩展函数，沿用 SHA-512 的已验证常数
// （降低自研风险面；规范中如实注明出处）。
func sig0(x uint64) uint64 {
	return bits.RotateLeft64(x, -1) ^ bits.RotateLeft64(x, -8) ^ (x >> 7)
}

func sig1(x uint64) uint64 {
	return bits.RotateLeft64(x, -19) ^ bits.RotateLeft64(x, -61) ^ (x >> 6)
}

// G 是幻线混合函数：对一条幻线上的三宫 (a,b,c) 做 BLAKE2 风格 ARX。
// 每次宫内模加均为 128 位进位链（跨爻进位），爻间交叉为
// "低爻吃对方高爻、高爻吃对方低爻"，旋转量按宫位置取自 rotsPal。
// 消息字 m0/m1 与轮常数 k 全量注入。
func G(x *[9]palace, a, b, c int, m0, m1, k uint64) {
	// 1) a += b + m（128 位进位链）
	t0, cy := bits.Add64(x[a].lo, x[b].lo, 0)
	t0, cy = bits.Add64(t0, m0, cy)
	t1, cy2 := bits.Add64(x[a].hi, x[b].hi, cy)
	t1, _ = bits.Add64(t1, m1, cy2)
	x[a].lo, x[a].hi = t0, t1

	// 2) b ^= a（爻间交叉）+ 按宫 b 旋转
	rb0, rb1 := rotsPal[b][0], rotsPal[b][1]
	x[b].lo = bits.RotateLeft64(x[b].lo^x[a].hi, -int(rb0))
	x[b].hi = bits.RotateLeft64(x[b].hi^x[a].lo, -int(rb1))

	// 3) c += b + (k,k)（双爻同注, 128 位链）
	t0, cy = bits.Add64(x[c].lo, x[b].lo, 0)
	t0, cy = bits.Add64(t0, k, cy)
	t1, _ = bits.Add64(x[c].hi, x[b].hi, cy)
	t1, _ = bits.Add64(t1, k, 0)
	x[c].lo, x[c].hi = t0, t1

	// 4) a ^= c（爻间交叉）+ 按宫 a 旋转
	ra0, ra1 := rotsPal[a][0], rotsPal[a][1]
	x[a].lo = bits.RotateLeft64(x[a].lo^x[c].hi, -int(ra0))
	x[a].hi = bits.RotateLeft64(x[a].hi^x[c].lo, -int(ra1))

	// 5) b += a（128 位链）
	t0, cy = bits.Add64(x[b].lo, x[a].lo, 0)
	t1, _ = bits.Add64(x[b].hi, x[a].hi, cy)
	x[b].lo, x[b].hi = t0, t1

	// 6) c ^= b（爻间交叉）+ 按宫 c 旋转
	rc0, rc1 := rotsPal[c][0], rotsPal[c][1]
	x[c].lo = bits.RotateLeft64(x[c].lo^x[b].hi, -int(rc0))
	x[c].hi = bits.RotateLeft64(x[c].hi^x[b].lo, -int(rc1))
}

// permute 执行九宫位置置换 σ：x'[σ[i]] = x[i]。
// 每 8 轮执行一次，72 轮共 9 次，σ⁹ = 恒等；每个字恰好遍历
// 全部 9 个宫位（中宫 / 边宫 / 角宫所有线型）。
func permute(x *[9]palace) {
	var t [9]palace
	for i := 0; i < 9; i++ {
		t[sigma[i]] = x[i]
	}
	*x = t
}

// expand 消息扩展：16 字 → 432 字（大端读入，SHA-512 σ 递推）。
func expand(block *[BlockBytes]byte) (w [MsgWords]uint64) {
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint64(block[i*8 : (i+1)*8])
	}
	for i := 16; i < MsgWords; i++ {
		w[i] = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16]
	}
	return
}

// compress 压缩一个 1024 位分组（生产版, 完整 72 主轮）。
// HAIFA 式注入：中宫低爻 += (counter+1)（块计数），高爻 += domK（域分离），
// 终局块高爻再异或 lastMark。72 主轮 + feed-forward。
func compress(h *[9]palace, block *[BlockBytes]byte, counter uint64, isLast bool) {
	compressR(h, block, counter, isLast, Rounds)
}

// compressR 轮数可变版（攻击套件缩减轮分析专用）。
// mainRounds < Rounds 时置换周期不再闭合——这正是差分分析要观察的状态。
func compressR(h *[9]palace, block *[BlockBytes]byte, counter uint64, isLast bool, mainRounds int) {
	var old, v [9]palace
	old = *h
	v = old

	// HAIFA 注入（中宫）
	t0, _ := bits.Add64(v[4].lo, counter+1, 0)
	t1, _ := bits.Add64(v[4].hi, domK, 0)
	v[4].lo, v[4].hi = t0, t1
	if isLast {
		v[4].hi ^= lastMark
	}

	w := expand(block)

	// 主轮：每轮 3 条幻线，编号 a=(3r mod 8) 起连续三条
	for r := 0; r < mainRounds; r++ {
		a := (3 * r) % 8
		for j := 0; j < 3; j++ {
			ln := lines[(a+j)%8]
			G(&v, ln[0], ln[1], ln[2], w[6*r+2*j], w[6*r+2*j+1], roundK[3*r+j])
		}
		if (r+1)%8 == 0 {
			permute(&v)
		}
	}

	// feed-forward：h = v ⊕ h_old（Davies–Meyer，宽管道全 9 宫链回）
	for i := 0; i < 9; i++ {
		h[i].lo = v[i].lo ^ old[i].lo
		h[i].hi = v[i].hi ^ old[i].hi
	}
}

// finalMix 常数收尾 9 轮（生产版）。
func finalMix(s *[9]palace, lenLo, lenHi uint64) (out [8]uint64) {
	return finalMixR(s, lenLo, lenHi, FinalRounds)
}

// finalMixR 收尾轮数可变版（攻击套件专用）。
func finalMixR(s *[9]palace, lenLo, lenHi uint64, finalRounds int) (out [8]uint64) {
	for r := Rounds; r < Rounds+finalRounds; r++ {
		a := (3 * r) % 8
		for j := 0; j < 3; j++ {
			var m0, m1 uint64
			if r == Rounds {
				switch j {
				case 0:
					m0, m1 = lenLo, lenHi
				case 1:
					m0, m1 = domK, lenLo^lenHi
				}
			}
			ln := lines[(a+j)%8]
			G(s, ln[0], ln[1], ln[2], m0, m1, roundK[3*r+j])
		}
	}
	for i := 0; i < 8; i++ {
		midLo := bits.RotateLeft64(s[4].lo, -int(projRot[i]))
		midHi := bits.RotateLeft64(s[4].hi, -int(projRot[(i+4)%8]))
		out[i] = s[i].lo ^ s[i].hi ^ midLo ^ midHi
	}
	return
}
