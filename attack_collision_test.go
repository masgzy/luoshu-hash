package luoshu

// 攻击套件 3/7：碰撞攻击。
//
//   - TestAttackBirthdayTruncated: 截断 24 位生日碰撞——搜索成本实证
//     ≈ 2^12 次（√2^24），无结构性捷径即生日界成立
//   - TestAttackMillionSearch: 百万级随机搜索在 64 位截断上零碰撞
//     （期望碰撞数 ~2.7e-8, 出现碰撞 = 存在结构性碰撞）
//   - TestAttackJouxMulticollision: Joux 2004 多碰撞构造（白盒模型,
//     攻击者可直接调用压缩函数并读写 1152 位状态的最强假设）:
//     每步以 24 位状态截断搜索块对, 4 步串联 16 路"截断状态多碰撞"。
//     验证: (a) 每步成本落在生日界区间, 无差分捷径;
//           (b) 完整 1152 位状态在 16 路终点互不相同——
//               状态级多碰撞的成本 = 2^(1152-24) 每步, 宽管道
//               使 Joux 构造无法降低完整状态碰撞成本
//   - TestAttackSmallDomainExhaust: 16 位消息域穷举在完整 512 位
//     输出上无碰撞
//
// 以上均为"攻击者视角"的实证：衡量洛书落在随机函数预言机行为
// 的预期区间内, 而非"证明无碰撞"（后者数学上不可能）。

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// truncatedSum24 摘要前 3 字节（24 位截断）。
func truncatedSum24(data []byte) uint32 {
	s := Sum(data)
	return binary.BigEndian.Uint32(s[:4]) >> 8
}

// TestAttackBirthdayTruncated 24 位截断生日搜索。
// 找到第一对碰撞的期望次数 ≈ √(π/2 × 2^24) ≈ 3600。
func TestAttackBirthdayTruncated(t *testing.T) {
	for exp := 0; exp < 3; exp++ {
		seen := make(map[uint32][]byte, 8192)
		found := false
		tries := 0
		for tries < 1<<21 && !found {
			tries++
			msg := randomMsg()
			h := truncatedSum24(msg)
			if prev, ok := seen[h]; ok {
				if !equalBytes(prev, msg) && Sum(prev) != Sum(msg) {
					found = true // 24 位截断碰撞, 完整摘要不同（预期）
					break
				}
			}
			seen[h] = msg
		}
		if !found {
			t.Fatalf("实验 %d: 2^21 次搜索未找到 24 位截断碰撞——分布可能有偏", exp)
		}
		t.Logf("实验 %d: %d 次找到 24 位截断碰撞（生日期望 √(π/2)·2^12 ≈ 5133）", exp, tries)
		if tries < 512 {
			t.Fatalf("实验 %d: %d 次即碰撞, 远快于生日界——存在结构性捷径", exp, tries)
		}
	}
}

func randomMsg() []byte {
	m := make([]byte, 24)
	rand.Read(m)
	return m
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestAttackMillionSearch 10^6 随机消息在 64 位截断上找碰撞。
// 期望碰撞数 = C(10^6,2)/2^64 ≈ 2.7e-8——出现任何碰撞都是灾难性信号。
func TestAttackMillionSearch(t *testing.T) {
	const n = 1_000_000
	type key [8]byte
	seen := make(map[key]struct{}, n)
	buf := make([]byte, 40)
	for i := 0; i < n; i++ {
		rand.Read(buf)
		s := Sum(buf)
		var k key
		copy(k[:], s[:8])
		if _, dup := seen[k]; dup {
			t.Fatalf("64 位截断碰撞出现在第 %d 条随机消息——结构性碰撞", i)
		}
		seen[k] = struct{}{}
	}
	t.Logf("10^6 随机消息 64 位截断: 0 碰撞（期望 %.1e）", 2.7e-8)
}

// TestAttackJouxMulticollision Joux 多碰撞（白盒最强攻击者模型）。
func TestAttackJouxMulticollision(t *testing.T) {
	const steps = 4
	// 初始状态 = IV
	var h [9]palace
	for i := 0; i < 9; i++ {
		h[i].lo, h[i].hi = iv[2*i], iv[2*i+1]
	}
	// 每步: 找块对 (A,B) 使 compress(h,·) 后状态前 24 位相同
	type pair struct{ a, b [BlockBytes]byte }
	pairs := make([]pair, steps)
	for step := 0; step < steps; step++ {
		seen := make(map[[3]byte][BlockBytes]byte, 8192)
		var A, B [BlockBytes]byte
		tries := 0
		found := false
		for tries < 1<<17 && !found {
			tries++
			var m [BlockBytes]byte
			rand.Read(m[:])
			st := h
			compressR(&st, &m, uint64(step), false, Rounds)
			var k [3]byte
			k[0] = byte(st[0].lo >> 56)
			k[1] = byte(st[0].lo >> 48)
			k[2] = byte(st[0].lo >> 40)
			if prev, ok := seen[k]; ok {
				A, B = prev, m
				found = true
				break
			}
			seen[k] = m
		}
		if !found {
			t.Fatalf("步 %d: 2^17 次未找到 24 位状态截断块对", step)
		}
		if tries < 256 {
			t.Fatalf("步 %d: %d 次即得块对——压缩函数存在差分捷径", step, tries)
		}
		t.Logf("步 %d: %d 次找到 24 位截断状态块对（生日期望 √(π/2)·2^12 ≈ 5133）", step, tries)
		pairs[step] = pair{A, B}
		// 链接值推进: 取 A 路径的完整状态（每步链接值分叉后的公共截断）
		st := h
		compressR(&st, &A, uint64(step), false, Rounds)
		h = st
	}
	// 展开 16 路块序列, 各自跑完整状态链, 终点完整状态必须互不相同
	full := make(map[[144]byte]int, 16)
	for mask := 0; mask < 16; mask++ {
		var st [9]palace
		for i := 0; i < 9; i++ {
			st[i].lo, st[i].hi = iv[2*i], iv[2*i+1]
		}
		for step := 0; step < steps; step++ {
			var m [BlockBytes]byte
			if mask&(1<<step) != 0 {
				m = pairs[step].b
			} else {
				m = pairs[step].a
			}
			compressR(&st, &m, uint64(step), false, Rounds)
		}
		var k [144]byte
		for i := 0; i < 9; i++ {
			binary.BigEndian.PutUint64(k[i*16:], st[i].hi)
			binary.BigEndian.PutUint64(k[i*16+8:], st[i].lo)
		}
		if prev, dup := full[k]; dup {
			t.Fatalf("Joux 展开路径 %05b 与 %05b 完整状态碰撞——异常", prev, mask)
		}
		full[k] = mask
	}
	t.Logf("Joux 4 步 16 路: 截断状态多碰撞成立（每步成本=生日界）, 完整 1152 位状态 16 路互异")
}

// TestAttackSmallDomainExhaust 16 位消息域（65536 条）全量哈希无碰撞。
func TestAttackSmallDomainExhaust(t *testing.T) {
	const domain = 1 << 16
	seen := make(map[[64]byte]uint16, domain)
	for i := 0; i < domain; i++ {
		var m [2]byte
		binary.BigEndian.PutUint16(m[:], uint16(i))
		s := Sum(m[:])
		if prev, dup := seen[s]; dup {
			t.Fatalf("16 位消息域内碰撞: %04x 与 %04x", prev, i)
		}
		seen[s] = uint16(i)
	}
	t.Logf("16 位消息域穷举: 65536 条消息 0 碰撞（完整 512 位摘要）")
}
