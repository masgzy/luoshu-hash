<div align="center">

# LuoShu-512

**A 512-bit cryptographic hash that outputs Chinese characters**

[![CI](https://github.com/masgzy/luoshu-hash/actions/workflows/ci.yml/badge.svg)](https://github.com/masgzy/luoshu-hash/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/masgzy/luoshu-hash?display_name=tag&sort=semver)](https://github.com/masgzy/luoshu-hash/releases)
[![Go Version](https://img.shields.io/badge/go-1.21%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![GoDoc](https://godoc.org/github.com/masgzy/luoshu-hash?status.svg)](https://pkg.go.dev/github.com/masgzy/luoshu-hash)
[![Go Report Card](https://goreportcard.com/badge/github.com/masgzy/luoshu-hash)](https://goreportcard.com/report/github.com/masgzy/luoshu-hash)

English | [简体中文](README.md)

</div>

---

> ⚠️ **Security warning: this algorithm has NOT received independent third-party cryptanalysis. Do NOT use it in any production security context.**
> Until at least two independent third-party analyses are published, use LuoShu for research, teaching, and experimentation only.
> See the [security disclaimer](#security-disclaimer).

## Overview

LuoShu-512 is a 512-bit hash function whose native output form is Chinese text. Any byte stream is reduced to **44 high-frequency Chinese characters plus a 7-hex-digit check code** — a digest that can be dictated, hand-copied, or printed, and verified offline without a computer.

```text
Input: "洛书"
Digest: 扭箭小查咋带埋宽带乔企码书醉璃志冰右计摆见强割泪悦碎队鼓壳代仔喝姻忍预妖跪塑着惧寿较凤综
Check:  003ff65
```

The construction is a wide-pipe Merkle–Damgård hash whose compression function is built on the Lo Shu magic square (a 3×3 grid of 128-bit palaces, 1152-bit total state) with BLAKE2-style ARX rounds. The full design rationale is documented in the LuoShu-512 specification PDF attached to each [release](https://github.com/masgzy/luoshu-hash/releases).

## Features

- **512-bit digest, three representations**: 128-char hex / 44 Chinese characters (low 484 bits of D, 11 bits per character, bijective) / 28-bit check code
- **Frozen 2048-character table**: top-2048 characters by frequency from a 600-million-token corpus; the table is the specification, carries a SHA-256 fingerprint, and is verifiable by any independent implementation
- **Losslessly decodable**: the 44 characters restore the 484 bits; combined with the check code, transcription errors (single-character substitution or transposition) are detected 100% — machine-asserted
- **Length-extension immunity**: triple defense (HAIFA block counter + finalization flag + 1152→512 projection), demonstrated by a controlled experiment where the bare-MD variant is broken while the real construction resists
- **Full open attack-verification suite**: avalanche, bit/character/run chi-square, birthday, Joux multicollision, million-message collision search, preimage, reduced-round differential, channel-independence tests — all reproducible from source
- **Zero-dependency pure Go**: single module, single static CLI binary

## Installation

Requires Go 1.21+.

```bash
go get github.com/masgzy/luoshu-hash
```

CLI:

```bash
go install github.com/masgzy/luoshu-hash/cmd/luoshu@latest
```

## Quick Start

```go
package main

import (
    "fmt"

    "github.com/masgzy/luoshu-hash"
)

func main() {
    data := []byte("any byte stream")

    fmt.Println(luoshu.SumHex(data))      // 512-bit hex (128 chars)
    fmt.Println(luoshu.SumChinese(data))  // 44 Chinese characters
    fmt.Println(luoshu.ChecksumHex(data)) // 7-char check code

    // Streaming (implements the standard hash.Hash interface)
    h := luoshu.New()
    h.Write([]byte("chunked "))
    h.Write([]byte("writes"))
    fmt.Printf("%x\n", h.Sum(nil))

    // Verify a hand-copied digest
    err := luoshu.VerifyChinese("44个汉字…", "003ff65")
    fmt.Println(err) // nil = OK
}
```

## CLI

```text
$ luoshu -s "洛书"
d9bdc81a…59eb2        # hex digest (128 chars)
扭箭小查…较凤综          # Chinese digest (44 chars)
003ff65                # check code

$ luoshu file.txt        # hash a file
$ cat bigfile | luoshu   # stdin
$ luoshu -x "44汉字" 003ff65  # verify mode
$ luoshu -z -s "洛书"   # Chinese output only
```

## Known Answers (KAT)

| Input | Digest (first 12 chars) | Check |
|---|---|---|
| `""` | 上炼坏侠症角谋制瞎壳见… | `05d6aa9` |
| `"abc"` | 瞬践统熬宋池预弟流婚继… | `afbae66` |
| `"洛书"` | 扭箭小查咋带埋宽带乔企… | `003ff65` |
| `"The quick brown fox jumps over the lazy dog"` | 束哲漫羞尊哈赏乔丰征啊锤… | `e75d58c` |

Full vectors are in the specification PDF and `luoshu_test.go`.

## Performance

Pure-Go software implementation, measured on 2-core x86-64 (`go test -bench`):

| Algorithm | Throughput (64KB blocks) | Notes |
|---|---:|---|
| SHA-256 | 1729 MB/s | SHA-NI accelerated |
| SHA-512 | 667 MB/s | hand-optimized asm path |
| **LuoShu** | **42 MB/s** | 1152-bit wide-pipe, soft ARX |

LuoShu is roughly an order of magnitude slower than SHA-512 under comparable software conditions. This is the explicit cost of the wide pipe (2.25× state width) and 128-bit carry-chain ARX; the specification contains the full performance analysis. Security maturity is not comparable to the SHA family — see the disclaimer.

## Security Disclaimer

1. LuoShu is an **engineering-grade design with empirical validation**: every machine-verifiable attack suite (avalanche, birthday, preimage, length extension, reduced-round differentials, Joux multicollision, million-message random search, and more) is open source and passing, with no statistically detectable deviation from random-oracle behavior.
2. LuoShu has **not** been analyzed by independent third parties. Prime-derived constants and the "no-complement / no-arithmetic-progression" rotation table are design hygiene, not security arguments.
3. Until at least two independent third-party cryptanalyses exist, do **not** use LuoShu in any production security context.
4. Any implementation can independently regenerate the constant tables (`scripts/gen_consts.py`, `gen_zhchars.py`) and cross-check against the KAT in `luoshu_test.go` — distrust any "LuoShu" implementation that fails the KAT.

## Project Layout

```text
luoshu.go          hash.Hash implementation (streaming/padding/finalize)
compress.go        compression function (G rounds/permutation/schedule/HAIFA/final mix)
const_gen.go       IV/round constants/lines/rotation tables (script-generated)
zh.go              Chinese encoding/decoding/check code
zhchars.go         2048-character table (frozen, SHA-256 fingerprint)
luoshu_test.go     KAT/determinism/structural machine assertions
attack_*_test.go   attack-verification suite (7 groups, reproducible)
bench_test.go      benchmarks
cmd/luoshu         CLI tool
scripts/           constant & table generation scripts (Python)
```

## Contributing

Issues and pull requests are welcome. For security-related findings, please report privately via GitHub Security Advisories instead of opening a public issue. All changes must pass the full test suite and `go vet`.

## License

[Apache License 2.0](LICENSE)
