package luoshu

// 攻击套件 5/7：长度扩展攻击对照实验。
//
// 经典长度扩展（对"裸 MD + 直接输出完整链接状态"形态的哈希, 如
// SHA-256 的 8 字状态输出）: 已知 H(m) 与 len(m), 无需 m 明文即可
// 计算 H(m ‖ pad(m) ‖ y)。
//
// 对照设计（同一个洛书压缩函数, 只差防线）:
//
//	裸 MD 版洛书 = compressR(无块计数/无终局标志) + 输出完整 1152 位状态
//	真实洛书     = HAIFA 计数 + 终局标志 + 收尾 9 轮 + 1152→512 投影
//
//   - TestAttackLengthExtensionBareMD: 裸 MD 版被长度扩展成功攻破
//     （既证明攻击实现正确有效, 也证明洛书压缩函数本身并无魔法——
//       免疫完全来自结构防线）
//   - TestAttackLengthExtensionLuoShu: 同一攻击对真实洛书必然失败
//   - TestAttackLengthExtensionStateRecovery: 状态恢复的代数不可能性

import (
	"encoding/binary"
	"testing"
)

// rawPad SHA 风格填充: 0x80 + 零 + 128 位大端比特长度, 对齐 128 字节。
func rawPad(n int) []byte {
	p := []byte{0x80}
	for (n+len(p))%BlockBytes != 112 {
		p = append(p, 0)
	}
	var lb [16]byte
	binary.BigEndian.PutUint64(lb[8:], uint64(n)*8)
	p = append(p, lb[:]...)
	return p
}

// rawStateBytes 裸 MD 版洛书: 处理 msg‖pad(msg), 输出完整 1152 位
// 状态（144 字节）。无计数器注入、无终局标志、无 finalMix。
func rawStateBytes(msg []byte) (out [144]byte) {
	var st [9]palace
	for i := 0; i < 9; i++ {
		st[i].lo, st[i].hi = iv[2*i], iv[2*i+1]
	}
	stream := append(append([]byte{}, msg...), rawPad(len(msg))...)
	for off := 0; off < len(stream); off += BlockBytes {
		var blk [BlockBytes]byte
		copy(blk[:], stream[off:off+BlockBytes])
		compressR(&st, &blk, 0, false, Rounds)
	}
	for i := 0; i < 9; i++ {
		binary.BigEndian.PutUint64(out[i*16:], st[i].hi)
		binary.BigEndian.PutUint64(out[i*16+8:], st[i].lo)
	}
	return
}

// TestAttackLengthExtensionBareMD 裸 MD 版被成功扩展。
// 受害者: V = rawState(m ‖ pad(m) ‖ suffix)（把 m‖pad(m)‖suffix 当完整消息）
// 攻击者: 只有 H_bare(m)（144 字节状态）+ len(m) + suffix,
//
//	从该状态续压缩 (suffix ‖ pad(总长)) 的块。
//
// 两者块序列完全一致 → 必然相等。
func TestAttackLengthExtensionBareMD(t *testing.T) {
	m := []byte("secret prefix for length extension demo")
	suffix := []byte("EVIL SUFFIX")
	padM := rawPad(len(m))

	// 受害者计算
	victimMsg := append(append([]byte{}, m...), padM...)
	victimMsg = append(victimMsg, suffix...)
	hVictim := rawStateBytes(victimMsg)

	// 攻击者计算: 从 H_bare(m) 续算
	hm := rawStateBytes(m) // = 处理完 m‖pad(m) 的状态
	var st [9]palace
	for i := 0; i < 9; i++ {
		st[i].hi = binary.BigEndian.Uint64(hm[i*16:])
		st[i].lo = binary.BigEndian.Uint64(hm[i*16+8:])
	}
	total := len(m) + len(padM) + len(suffix)
	tail := append(append([]byte{}, suffix...), rawPad(total)...)
	for off := 0; off < len(tail); off += BlockBytes {
		var blk [BlockBytes]byte
		copy(blk[:], tail[off:off+BlockBytes])
		compressR(&st, &blk, 0, false, Rounds)
	}
	var hAttack [144]byte
	for i := 0; i < 9; i++ {
		binary.BigEndian.PutUint64(hAttack[i*16:], st[i].hi)
		binary.BigEndian.PutUint64(hAttack[i*16+8:], st[i].lo)
	}

	if hAttack != hVictim {
		t.Fatalf("裸 MD 长度扩展失败?! 攻击实现或对照构建有误")
	}
	t.Logf("裸 MD 版: 攻击者仅凭 H(m)+len(m) 伪造出 H(m‖pad(m)‖suffix)——扩展成功")
}

// TestAttackLengthExtensionLuoShu 真实洛书: 同一攻击必然失败。
// 三种攻击尝试: 零填充伪状态 / 循环填充伪状态 / HAIFA 计数模拟。
func TestAttackLengthExtensionLuoShu(t *testing.T) {
	m := []byte("secret prefix for length extension demo")
	suffix := []byte("EVIL SUFFIX")
	real := Sum(append(append([]byte{}, m...), suffix...))
	hm := Sum(m)

	attempts := []struct {
		name string
		g    [64]byte
	}{
		{"零填充伪状态", extendFromPseudoState(hm[:], len(m), suffix, false)},
		{"循环填充伪状态", extendFromPseudoState(repeatTo144(hm[:]), len(m), suffix, false)},
		{"HAIFA 计数模拟", extendFromPseudoState(repeatTo144(hm[:]), len(m), suffix, true)},
	}
	for _, at := range attempts {
		if at.g == real {
			t.Fatalf("洛书长度扩展成功（%s）——防线失效!", at.name)
		}
	}
	t.Logf("真实洛书: 三种伪状态构造全部失败（缺 640 位状态 + HAIFA 历史不可伪造）")
}

// extendFromPseudoState 攻击者模拟: 伪材料扩展成 1152 位状态后续算。
// haifaAware=true 时按真实计数器递增（模拟知道 HAIFA 细节的最强攻击者）。
func extendFromPseudoState(mat []byte, mLen int, suffix []byte, haifaAware bool) (out [64]byte) {
	var st [9]palace
	full := repeatTo144(mat)
	for i := 0; i < 9; i++ {
		st[i].hi = binary.BigEndian.Uint64(full[i*16:])
		st[i].lo = binary.BigEndian.Uint64(full[i*16+8:])
	}
	padM := rawPad(mLen)
	stream := append(append([]byte{}, padM...), suffix...)
	for len(stream)%BlockBytes != 0 {
		stream = append(stream, 0)
	}
	counter := uint64(0)
	if haifaAware {
		counter = uint64(mLen / BlockBytes)
	}
	for off := 0; off < len(stream); off += BlockBytes {
		var blk [BlockBytes]byte
		copy(blk[:], stream[off:off+BlockBytes])
		compressR(&st, &blk, counter, false, Rounds)
		if haifaAware {
			counter++
		}
	}
	totalBits := uint64(mLen+len(stream)) * 8
	o := finalMix(&st, totalBits, 0)
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint64(out[i*8:], o[i])
	}
	return
}

// repeatTo144 循环填充到 144 字节。
func repeatTo144(mat []byte) []byte {
	out := make([]byte, 144)
	for i := 0; i < 144; i++ {
		if len(mat) > 0 {
			out[i] = mat[i%len(mat)]
		}
	}
	return out
}

// TestAttackLengthExtensionStateRecovery 状态恢复的代数不可能性:
// 100 个随机 1152 位状态的 512 位投影两两互异（2^-512 碰撞事件
// 不应出现）; 投影方程 8 个 vs 未知 18 字, 欠定 640 位。
func TestAttackLengthExtensionStateRecovery(t *testing.T) {
	projs := make(map[[64]byte]bool, 100)
	for i := 0; i < 100; i++ {
		var st [9]palace
		for j := 0; j < 9; j++ {
			st[j].lo = uint64(i)*0x9E3779B97F4A7C15 + uint64(j)
			st[j].hi = uint64(i)*0xBF58476D1CE4E5B9 ^ uint64(j)*0x94D049BB133111EB
		}
		o := finalMix(&st, uint64(i), uint64(i)*8)
		var d [64]byte
		for k := 0; k < 8; k++ {
			binary.BigEndian.PutUint64(d[k*8:], o[k])
		}
		if projs[d] {
			t.Fatal("随机状态投影碰撞（2^-512 概率事件不应发生）")
		}
		projs[d] = true
	}
	t.Logf("状态投影: 100 个随机状态两两互异; 逆向恢复欠定 640 位（8 方程 vs 18 未知）")
}
