package luoshu

import (
	"encoding/binary"
	"hash"
)

// digest 持有洛书哈希的全部状态。
type digest struct {
	s            [9]palace // 1152 位九宫状态
	buf          [BlockBytes]byte
	n            int    // buf 中已缓冲字节数
	lenLo, lenHi uint64 // 已写入总比特数（128 位）
	counter      uint64 // 已压缩分组数
	// 攻击测试专用轮数覆盖（0 = 生产默认 Rounds/FinalRounds）。
	// 生产代码永远不设置这两个字段。
	mainRounds, finalRounds int
}

// effRounds 返回生效轮数。
func (d *digest) effRounds() (int, int) {
	mr, fr := d.mainRounds, d.finalRounds
	if mr == 0 {
		mr = Rounds
	}
	if fr == 0 {
		fr = FinalRounds
	}
	return mr, fr
}

// New 返回一个新的洛书 LuoShu-512 哈希实例（实现 hash.Hash）。
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// Reset 重置到初始状态。实现 hash.Hash。
// 敏感缓冲与状态先零化再重注 IV，防止内存残留。
func (d *digest) Reset() {
	// 零化（敏感数据）
	for i := range d.s {
		d.s[i].lo, d.s[i].hi = 0, 0
	}
	for i := range d.buf {
		d.buf[i] = 0
	}
	d.n = 0
	d.lenLo, d.lenHi = 0, 0
	d.counter = 0
	// 重注 IV：18 字 = 9 宫 × 双爻
	for i := 0; i < 9; i++ {
		d.s[i].lo = iv[2*i]
		d.s[i].hi = iv[2*i+1]
	}
}

// Size 返回摘要字节数（64 = 512 位）。实现 hash.Hash。
func (d *digest) Size() int { return 64 }

// BlockSize 返回分组字节数（128 = 1024 位）。实现 hash.Hash。
func (d *digest) BlockSize() int { return BlockBytes }

// Write 写入数据。实现 hash.Hash。永不返回错误。
// 凑满 1024 位立即压缩，缓冲区在自身数组上操作，零额外分配。
func (d *digest) Write(p []byte) (int, error) {
	n := len(p)
	// 128 位比特长度累计（先加低位，溢出进高位）
	bits := uint64(n) * 8
	newLo := d.lenLo + bits
	if newLo < d.lenLo {
		d.lenHi++
	}
	d.lenLo = newLo

	for len(p) > 0 {
		c := copy(d.buf[d.n:], p)
		d.n += c
		p = p[c:]
		if d.n == BlockBytes {
			mr, _ := d.effRounds()
			compressR(&d.s, &d.buf, d.counter, false, mr)
			d.counter++
			d.n = 0
		}
	}
	return n, nil
}

// Sum 以 64 字节（512 位）摘要追加到 in 并返回。实现 hash.Hash。
// 在状态副本上 finalize，不改变当前哈希状态（不重置）；
// 重置必须显式调用 Reset。
func (d *digest) Sum(in []byte) []byte {
	e := *d
	var out [64]byte
	e.final(&out)
	return append(in, out[:]...)
}

// final 完成填充、压缩终局块、收尾轮与投影，写出 512 位摘要。
// SHA-512 风格填充：0x80 + 零 + 128 位比特长度，使总长 ≡ 0 (mod 1024)。
func (d *digest) final(out *[64]byte) {
	// 构造填充块（最多两块 = 256 字节）
	var pad [2 * BlockBytes]byte
	copy(pad[:d.n], d.buf[:d.n])
	pad[d.n] = 0x80

	// 单块可容纳：残余 + 0x80 + 16 字节长度 ≤ 128
	// 即 d.n ≤ 111；否则需要两块
	var nBlocks int
	if d.n <= BlockBytes-17 {
		nBlocks = 1
	} else {
		nBlocks = 2
	}
	total := nBlocks * BlockBytes

	// 长度字段：占最后一个块的末尾 16 字节（128 位大端）
	lenOff := total - 16
	binary.BigEndian.PutUint64(pad[lenOff:], d.lenHi)
	binary.BigEndian.PutUint64(pad[lenOff+8:], d.lenLo)

	mr, fr := d.effRounds()
	for off := 0; off < total; off += BlockBytes {
		var blk [BlockBytes]byte
		copy(blk[:], pad[off:off+BlockBytes])
		isLast := off+BlockBytes == total
		compressR(&d.s, &blk, d.counter, isLast, mr)
		d.counter++
	}

	// 收尾 9 轮（再注入消息长度与域常数）+ 九宫折八卦投影
	o := finalMixR(&d.s, d.lenLo, d.lenHi, fr)
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint64(out[i*8:(i+1)*8], o[i])
	}
	// 零化工作区（敏感数据）
	for i := range pad {
		pad[i] = 0
	}
}

// Sum 返回 data 的 512 位摘要（64 字节大端）。
func Sum(data []byte) (sum [64]byte) {
	d := New()
	d.Write(data)
	copy(sum[:], d.Sum(nil))
	return
}
