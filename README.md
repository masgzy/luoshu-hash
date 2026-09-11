<div align="center">

# 洛书 LuoShu-512

**输出汉字的 512 位密码学哈希算法**

[![CI](https://github.com/masgzy/luoshu-hash/actions/workflows/ci.yml/badge.svg)](https://github.com/masgzy/luoshu-hash/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/masgzy/luoshu-hash?display_name=tag&sort=semver)](https://github.com/masgzy/luoshu-hash/releases)
[![Go Version](https://img.shields.io/badge/go-1.21%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![GoDoc](https://godoc.org/github.com/masgzy/luoshu-hash?status.svg)](https://pkg.go.dev/github.com/masgzy/luoshu-hash)
[![Go Report Card](https://goreportcard.com/badge/github.com/masgzy/luoshu-hash)](https://goreportcard.com/report/github.com/masgzy/luoshu-hash)

[English](README_EN.md) | 简体中文

</div>

---

> ⚠️ **安全警告：本算法尚未经过独立第三方密码分析，不得用于任何生产安全场景。**
> 在获得至少两个独立第三方的密码分析报告之前，请仅将洛书用于研究、教学与实验。
> 详细说明见[安全声明](#安全声明)。

## 简介

洛书（LuoShu-512）是一个以中文汉字为输出形态的 512 位哈希算法。任意字节流经洛书计算后，得到 **44 个高频汉字 + 7 位十六进制校验码**——摘要可以直接口述、手抄、印刷，且可无损校验。

```text
输入: "洛书"
输出: 扭箭小查咋带埋宽带乔企码书醉璃志冰右计摆见强割浮存殖丁谋面按缝赌爽媒燃答综谱耶弱撩凉纳秘
校验: cf7c77b
```

算法骨架为宽管道 Merkle–Damgård 结构，压缩函数基于九宫洛书幻方（3×3 宫，每宫 128 位，总状态 1152 位），轮函数为 BLAKE2 风格 ARX。完整设计说明见[《洛书 LuoShu-512 规范》](https://github.com/masgzy/luoshu-hash/releases)（随发布附带 PDF）。

## 特性

- **512 位摘要，三种表示**：128 字符 hex / 44 汉字（D 的前 484 位，11 bit/字双射编码）/ 28 bit 校验码
- **2048 字表冻结**：六亿知乎语料字频前 2048 字，表即规范、带 SHA-256 指纹，任意实现可校验
- **可无损解码**：44 汉字可还原 484 位；配 7 字符校验码可离线检错（单字替换/换位 100% 检出，机器断言）
- **长度扩展免疫**：HAIFA 块计数 + 终局标志 + 1152→512 投影三重防线（附对照实验：裸 MD 形态被攻破，真实形态免疫）
- **全套攻击验证套件开源**：雪崩、位频/字分布/游程卡方、生日/Joux 多碰撞、百万级碰撞搜索、原像、差分缩减轮、双通道独立性——随源码可独立复现
- **零依赖纯 Go**：单模块、无第三方依赖、单一静态二进制 CLI

## 安装

要求 Go 1.21+。

```bash
go get github.com/masgzy/luoshu-hash
```

命令行工具：

```bash
go install github.com/masgzy/luoshu-hash/cmd/luoshu@latest
```

## 快速开始

```go
package main

import (
    "fmt"

    "github.com/masgzy/luoshu-hash"
)

func main() {
    data := []byte("任何字节流")

    fmt.Println(luoshu.SumHex(data))     // 512 位 hex（128 字符）
    fmt.Println(luoshu.SumChinese(data)) // 44 汉字摘要
    fmt.Println(luoshu.ChecksumHex(data)) // 7 字符校验码

    // 流式（实现标准 hash.Hash, 可用于 io.Writer 管道）
    h := luoshu.New()
    h.Write([]byte("分"))
    h.Write([]byte("段写入"))
    fmt.Printf("%x\n", h.Sum(nil))

    // 校验抄写的汉字摘要
    err := luoshu.VerifyChinese("44个汉字…", "cf7c77b")
    fmt.Println(err) // nil = 校验通过
}
```

## 命令行

```text
$ luoshu -s "洛书"
d9bdc81a…f1015d        # hex 摘要（128 字符）
扭箭小查…凉纳秘          # 汉字摘要（44 字）
cf7c77b                # 校验码

$ luoshu 文件名.txt      # 对文件取哈希
$ cat 大文件 | luoshu    # 标准输入
$ luoshu -x "44汉字" 校验码   # 校验模式
$ luoshu -z -s "洛书"   # 只输出汉字
```

## 已知答案（KAT）

| 输入 | 汉字摘要（前 12 字） | 校验码 |
|---|---|---|
| `""` | 上炼坏侠症角谋制瞎壳见… | `b553993` |
| `"abc"` | 瞬践统熬宋池预弟流婚继… | `1f7ba80` |
| `"洛书"` | 扭箭小查咋带埋宽带乔企… | `cf7c77b` |
| `"The quick brown fox jumps over the lazy dog"` | 束哲漫羞尊哈赏乔丰征啊锤… | `b7f8c11` |

完整向量见[规范 PDF](https://github.com/masgzy/luoshu-hash/releases)与 `luoshu_test.go`。

## 性能

纯 Go 软实现，2 核 x86-64 实测（`go test -bench`）：

| 算法 | 吞吐（64KB 块） | 说明 |
|---|---:|---|
| SHA-256 | 1729 MB/s | SHA-NI 指令集加速 |
| SHA-512 | 667 MB/s | 汇编优化路径 |
| **洛书** | **42 MB/s** | 1152 位宽管道软实现 |

洛书比同条件 SHA-512 软实现慢约一个数量级。这是宽管道（2.25× 状态宽度）与 128 位进位链 ARX 的显式设计代价，规范中有完整性能分析。安全成熟度不可与 SHA 系列相提并论，见安全声明。

## 安全声明

1. 洛书是**工程级设计与实证**：全部可机器验证的攻击套件（雪崩、生日、原像、长度扩展、差分缩减轮、Joux 多碰撞、百万级随机搜索等）已开源并全部通过，测试结果与随机预言机行为无统计偏差。
2. 洛书**没有**经过独立第三方密码分析。素数常数与"无互补/无等差"旋转量表属于设计卫生，不是安全论据。
3. 在获得至少两个独立第三方的密码分析之前，**不得用于任何生产安全场景**。请用于研究、教学、实验。
4. 任何实现都可以用源码中 `scripts/gen_consts.py`、`gen_zhchars.py` 独立复现常数表与汉字表，用 `luoshu_test.go` 中的 KAT 交叉验证——警惕任何无法通过 KAT 的"洛书"实现。

## 项目结构

```text
luoshu.go          hash.Hash 接口实现（流式/填充/finalize）
compress.go        压缩函数（G 轮函数/置换/消息扩展/HAIFA/收尾）
const_gen.go       IV/轮常数/幻线/旋转量表（脚本生成, 可复现）
zh.go              汉字编码/解码/校验码
zhchars.go         2048 字表（冻结, SHA-256 指纹）
luoshu_test.go     KAT/确定性/结构常量机器断言
attack_*_test.go   攻击验证套件（7 组, 全部可独立复现）
bench_test.go      性能基准
cmd/luoshu         CLI 工具
scripts/           常数与字表生成脚本（Python）
```

## 贡献

欢迎提交 Issue 与 Pull Request。安全相关的发现请先私下报告（GitHub Security Advisory），勿在公开 Issue 中披露未修复的漏洞。所有代码变更需通过全部测试与 `go vet`。

## 许可证

[Apache License 2.0](LICENSE)
