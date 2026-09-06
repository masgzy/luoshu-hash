# 更新日志 / Changelog

本文件格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [1.0.0] - 2025-09-06

首个公开发布版本。

### 新增（Added）

- 洛书 LuoShu-512 哈希算法完整实现：1152 位九宫宽管道 Merkle–Damgård，
  1024 位分组，72 主轮 + 9 收尾轮，BLAKE2 风格 ARX 轮函数
- 三种摘要表示：128 字符 hex / 44 汉字（484 位，11 bit/字双射）/ 28 bit 校验码
- 2048 高频汉字表（六亿知乎语料字频，冻结，SHA-256 指纹自检）
- 汉字摘要无损解码与离线校验（`DecodeChinese` / `VerifyChinese`）
- `hash.Hash` 流式接口（`Write` / `Sum` / `Reset` / `Size` / `BlockSize`）
- 命令行工具 `cmd/luoshu`：字符串/文件/标准输入哈希与校验模式
- 已知答案测试（KAT）4 组向量冻结
- 攻击验证套件 7 组全部开源：雪崩（总体/位级/卡方）、位频与字分布卡方、
  游程检验、生日碰撞、Joux 多碰撞（白盒模型）、百万级碰撞搜索、
  原像与第二原像、长度扩展对照实验（裸 MD 攻破 vs 真实结构免疫）、
  差分缩减轮扩散曲线、双通道独立性、边界与状态残留
- 结构常量机器断言：置换闭合性（σ⁹ = 恒等）、旋转量表卫生
  （无互补/等差/倍数/倍角/半周期）、幻线魔性和、轮常数计数自洽
- 常数与字表生成脚本（`scripts/`，Python），支持第三方独立复现
- GitHub Actions CI：三操作系统 × 三 Go 版本测试矩阵、竞态检测、
  覆盖率门禁（≥90%）、五平台交叉编译、tag 触发发布流程
- 中文完整规范 PDF（随发布附件提供）

### 安全（Security）

- 安全声明：本算法未经过独立第三方密码分析，不得用于生产安全场景；
  在获得至少两个独立第三方分析之前仅限研究与教学用途

[Unreleased]: https://github.com/masgzy/luoshu-hash/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/masgzy/luoshu-hash/releases/tag/v1.0.0
