package luoshu

// 攻击套件 4/7：原像与第二原像攻击实证。
//
//   - TestAttackPreimage24: 24 位截断原像搜索, 命中成本 ≈ 2^24 的一半
//     （随机预言机行为: k 次尝试命中率 k/2^24）
//   - TestAttackPreimageNoShortcut: 固定差分/结构化消息族的原像搜索
//     无捷径——结构化尝试族的命中率与随机族一致
//   - TestAttackSecondPreimageSmall: 小域第二原像（对已知消息 m 找
//     m'≠m 同摘要, 24 位截断域内演示成本特性）
//
// 原像对 512 位输出不存在可行攻击; 此处验证的是"在可穷举的截断
// 域内, 行为与随机预言机无偏差"——即无捷径结构。

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// TestAttackPreimage24 24 位截断原像: 2^20 次尝试命中 2 次左右。
// 随机预言机: 命中数 ~ Poisson(2^20/2^24 = 1/16)。
// 断言: 命中数 ≤ 20（任何更多 = 结构性偏置）且不强制命中。
func TestAttackPreimage24(t *testing.T) {
	target := truncatedSum24([]byte("洛书原像目标"))
	hits := 0
	const tries = 1 << 20
	buf := make([]byte, 24)
	for i := 0; i < tries; i++ {
		rand.Read(buf)
		if truncatedSum24(buf) == target {
			hits++
		}
	}
	t.Logf("2^20 次随机原像搜索: 命中 %d 次（泊松期望 %.2f）", hits, 0.0625)
	if hits > 20 {
		t.Fatalf("命中 %d 次远超泊松期望——截断域原像存在结构性捷径", hits)
	}
}

// TestAttackPreimageNoShortcut 结构化消息族（等差/重复/低位置位）
// 的原像搜索命中率与随机族一致——排除"特定结构消息更易命中"。
func TestAttackPreimageNoShortcut(t *testing.T) {
	target := truncatedSum24([]byte("结构化目标"))
	// 三种结构化族, 各 2^18 次尝试, 统计命中
	families := map[string]func(i int) []byte{
		"等差族": func(i int) []byte {
			var m [8]byte
			binary.BigEndian.PutUint64(m[:], uint64(i)*0x9E3779B1)
			return m[:]
		},
		"计数族": func(i int) []byte {
			var m [8]byte
			binary.BigEndian.PutUint64(m[:], uint64(i))
			return m[:]
		},
		"低汉明重": func(i int) []byte {
			var m [8]byte
			// 3 位置 1 的消息族
			binary.BigEndian.PutUint64(m[:], uint64(1)<<(i%40)|uint64(1)<<(i/40%40)|uint64(1)<<((i/1600)%64))
			return m[:]
		},
	}
	for name, gen := range families {
		hits := 0
		for i := 0; i < 1<<18; i++ {
			if truncatedSum24(gen(i)) == target {
				hits++
			}
		}
		// 随机期望 2^18/2^24 = 1/16
		t.Logf("%s: 2^18 次命中 %d（期望 ~0.06）", name, hits)
		if hits > 8 {
			t.Fatalf("%s 命中 %d 次——结构化消息族存在原像捷径", name, hits)
		}
	}
}

// TestAttackSecondPreimageSmall 第二原像（20 位截断域演示）:
// 对 m="洛书" 找 m'≠m 使截断摘要相同。第二原像是逐点命中问题
// （不同于生日碰撞）: 期望尝试 ~2^20 = 100 万次, 几何分布。
func TestAttackSecondPreimageSmall(t *testing.T) {
	m := []byte("洛书")
	target := truncatedSum24(m) >> 4 // 20 位截断
	found := false
	tries := 0
	for tries < 1<<22 && !found {
		tries++
		m2 := randomMsg()
		if truncatedSum24(m2)>>4 == target {
			if !equalBytes(m, m2) && Sum(m) != Sum(m2) {
				found = true // 截断第二原像, 完整摘要不同（预期）
			}
		}
	}
	if !found {
		t.Fatal("2^22 次未找到 20 位截断第二原像——分布可能有偏（命中概率应 > 98%）")
	}
	t.Logf("第二原像(20 位截断): %d 次找到（逐点命中期望 2^20, 几何分布）", tries)
	if tries < 1<<16 {
		t.Fatalf("仅 %d 次找到截断第二原像——远快于 2^20, 存在结构捷径", tries)
	}
}
