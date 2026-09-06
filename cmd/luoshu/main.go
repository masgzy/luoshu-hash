// luoshu 命令行工具：对文件或字符串计算洛书 LuoShu-512 摘要。
//
// 用法:
//
//	luoshu [选项] [文件...]
//
// 选项:
//
//	-s 字符串   对指定字符串取哈希（与文件参数互斥）
//	-x          校验模式: luoshu -x "44汉字" 校验码
//	-q          只输出十六进制摘要
//	-z          只输出汉字摘要
//
// 无文件参数且未指定 -s 时读取标准输入。
// 常规输出为三行：hex（128 字符）、汉字（44 字）、校验（7 hex）。
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	luoshu "github.com/masgzy/luoshu-hash"
)

func main() {
	var (
		str    = flag.String("s", "", "对指定字符串取哈希")
		verify = flag.Bool("x", false, `校验模式: luoshu -x "44汉字" 校验码`)
		quiet  = flag.Bool("q", false, "只输出十六进制摘要")
		zhOnly = flag.Bool("z", false, "只输出汉字摘要")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "洛书 LuoShu-512 哈希工具\n\n用法:\n  luoshu [选项] [文件...]\n\n选项:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *verify {
		args := flag.Args()
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, `校验模式用法: luoshu -x "44汉字" 校验码`)
			os.Exit(2)
		}
		if err := luoshu.VerifyChinese(args[0], args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "校验失败:", err)
			os.Exit(1)
		}
		fmt.Println("校验通过：汉字与校验码一致")
		return
	}

	args := flag.Args()
	if *str != "" && len(args) > 0 {
		fmt.Fprintln(os.Stderr, "-s 与文件参数互斥")
		os.Exit(2)
	}

	process := func(name string, data []byte) {
		if *quiet {
			fmt.Printf("%s  %s\n", luoshu.SumHex(data), name)
			return
		}
		if *zhOnly {
			// 纯 44 字输出, 无前缀——便于管道与校验模式衔接
			fmt.Println(luoshu.SumChinese(data))
			return
		}
		if name != "" {
			fmt.Printf("== %s ==\n", name)
		}
		fmt.Printf("hex  : %s\n", luoshu.SumHex(data))
		fmt.Printf("汉字 : %s\n", luoshu.SumChinese(data))
		fmt.Printf("校验 : %s\n", luoshu.ChecksumHex(data))
	}

	switch {
	case *str != "":
		process("", []byte(*str))
	case len(args) > 0:
		for _, fn := range args {
			data, err := os.ReadFile(fn)
			if err != nil {
				fmt.Fprintln(os.Stderr, "读取失败:", err)
				os.Exit(1)
			}
			process(fn, data)
		}
	default:
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "读取 stdin 失败:", err)
			os.Exit(1)
		}
		process("", data)
	}
}
