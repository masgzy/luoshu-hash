# -*- coding: utf-8 -*-
"""洛书 LuoShu-512 旋转量表卫生检查与全约束搜索
约束（按密码学设计卫生标准）：
  1. 无互补对:      x + y != 64        (ROTR(x,r) == ROTL(x,64-r))
  2. 无等差三元组:  a + c != 2*b       (RX 差分可预测传播)
  3. 无倍数对:      y % x != 0         (公倍数链)
  4. 无倍角关系:    y != 2x mod 64     (旋转平移结构)
  5. 无半周期:      32 不在表内        (64/2 自抵消)
打分: 低/中/高旋转区均衡 + 相邻差多样性
"""
from itertools import combinations

POOL = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61]

def complementary(t):
    s = set(t)
    return sorted((x, 64 - x) for x in s if x < 32 and (64 - x) in s)

def arithmetic_triples(t):
    return [(a, b, c) for a, b, c in combinations(sorted(t), 3) if a + c == 2 * b]

def multiple_pairs(t):
    return [(x, y) for x, y in combinations(sorted(t), 2) if y % x == 0]

def doubling_pairs(t):
    out = []
    s = set(t)
    for x in t:
        if (2 * x) % 64 in s and (2 * x) % 64 != x:
            out.append((x, (2 * x) % 64))
    return sorted(set(out))

def check(name, t):
    print(f"[{name}] {t}")
    print(f"  互补对     : {complementary(t) or '无 ✓'}")
    print(f"  等差三元组 : {arithmetic_triples(t) or '无 ✓'}")
    print(f"  倍数对     : {multiple_pairs(t) or '无 ✓'}")
    print(f"  倍角对     : {doubling_pairs(t) or '无 ✓'}")
    print(f"  半周期 32  : {'存在 ✗' if 32 in t else '无 ✓'}")
    ok = not (complementary(t) or arithmetic_triples(t) or multiple_pairs(t) or doubling_pairs(t) or 32 in t)
    print(f"  结论       : {'✅ 通过' if ok else '❌ 不通过'}\n")
    return ok

# ---- 1) 验证 v2 专家表（声称"无等差"） ----
check("专家表(v2提议)", [13, 19, 23, 29, 37, 43, 53, 59, 61])

# ---- 2) 全约束搜索 ----
best, best_score = None, None
count = 0
for cand in combinations(POOL, 9):
    if 32 in cand: continue
    if complementary(cand): continue
    if arithmetic_triples(cand): continue
    if multiple_pairs(cand): continue
    if doubling_pairs(cand): continue
    count += 1
    low = sum(1 for x in cand if x <= 19)
    mid = sum(1 for x in cand if 20 <= x <= 45)
    high = sum(1 for x in cand if x >= 46)
    balance = abs(low - 3) + abs(mid - 3) + abs(high - 3)
    diffs = [cand[i + 1] - cand[i] for i in range(8)]
    variety = len(set(diffs))
    spread = max(cand) - min(cand)
    score = (balance, -variety, -spread)
    if best_score is None or score < best_score:
        best, best_score = cand, score

print(f"全约束搜索: 池大小 {len(POOL)}, 通过约束的 9 元素组合共 {count} 个")
print(f"最优表: {list(best)}  (均衡偏差={best_score[0]}, 差值种类={-best_score[1]}, 跨度={-best_score[2]})\n")

# ---- 3) 复检最优表 ----
FINAL = list(best)
check("洛书v3定稿表", FINAL)

# ---- 4) 生成宫位双爻映射（洛书数索引 + 错4相位） ----
LUOSHU = [4, 9, 2, 3, 5, 7, 8, 1, 6]  # 行优先: 宫0..8
print("宫位双爻旋转量映射 (宫i: 爻0=P[(L-1)%9], 爻1=P[(L-1+4)%9]):")
pairs = []
for i, L in enumerate(LUOSHU):
    r0 = FINAL[(L - 1) % 9]
    r1 = FINAL[(L - 1 + 4) % 9]
    pairs.append((r0, r1))
    print(f"  宫{i} (洛书数{L}): 爻0={r0:2d}  爻1={r1:2d}")

# 双爻对内部 + 跨宫两两组合的卫生复检
combos = []
for i, (r0, r1) in enumerate(pairs):
    if r0 + r1 == 64: combos.append((i, r0, r1, "宫内互补"))
for i in range(9):
    for j in range(i + 1, 9):
        for a in pairs[i]:
            for b in pairs[j]:
                if a + b == 64: combos.append((i, j, a, b, "跨宫互补"))
print(f"\n双爻组合复检: {'✅ 无互补结构' if not combos else combos}")
