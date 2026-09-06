package luoshu

// 性能基准: 洛书 LuoShu-512 vs SHA-256 / SHA-512。
//
// 运行: go test -bench . -benchmem
//
// 预期与诚实声明（写入规范）:
//   - 洛书为软实现 ARX 128 位进位链, 且状态宽 1152 位（SHA-512 的 2.25 倍）,
//     轮内 3 宫×128 位更新——吞吐低于 SHA-512 的软实现是设计代价,
//     属"宽管道安全余量"的显式成本, 不是缺陷隐瞒。
//   - SHA 系列有数十年汇编优化（SHA-NI 指令集）, 洛书无任何汇编路径。
//   - 具体倍率见 t.Logf 输出与 README 性能表。

import (
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

var benchSizes = []struct {
	name string
	n    int
}{
	{"64B", 64},
	{"1KB", 1024},
	{"64KB", 64 << 10},
	{"1MB", 1 << 20},
}

var sink []byte

func BenchmarkLuoShu(b *testing.B) {
	for _, sz := range benchSizes {
		data := make([]byte, sz.n)
		for i := range data {
			data[i] = byte(i)
		}
		b.Run(sz.name, func(b *testing.B) {
			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				s := Sum(data)
				sink = s[:]
			}
		})
	}
}

func BenchmarkSHA256(b *testing.B) {
	for _, sz := range benchSizes {
		data := make([]byte, sz.n)
		for i := range data {
			data[i] = byte(i)
		}
		b.Run(sz.name, func(b *testing.B) {
			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				s := sha256.Sum256(data)
				sink = s[:]
			}
		})
	}
}

func BenchmarkSHA512(b *testing.B) {
	for _, sz := range benchSizes {
		data := make([]byte, sz.n)
		for i := range data {
			data[i] = byte(i)
		}
		b.Run(sz.name, func(b *testing.B) {
			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				s := sha512.Sum512(data)
				sink = s[:]
			}
		})
	}
}

// BenchmarkLuoShuChinese 汉字输出编码开销。
func BenchmarkLuoShuChinese(b *testing.B) {
	data := make([]byte, 1024)
	b.SetBytes(1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sink = []byte(SumChinese(data))
	}
}

// BenchmarkLuoShuReuse 流式复用（sync.Pool 场景）。
func BenchmarkLuoShuReuse(b *testing.B) {
	data := make([]byte, 64<<10)
	h := New()
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(data)
		h.Sum(nil)
	}
}
