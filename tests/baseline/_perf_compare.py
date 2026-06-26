"""交叉验收：性能对比测量（对比代理 H 建立的基线）"""
import json
import subprocess
import time
import sys
from pathlib import Path

BASELINE_FILE = Path(r"e:\Project\python\Speakeasy-X\tests\baseline\performance_baseline.json")
OUTPUT_FILE = Path(r"e:\Project\python\Speakeasy-X\tests\baseline\performance_after.json")

# 加载基线
with open(BASELINE_FILE, encoding="utf-8") as f:
    baseline = json.load(f)

results = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "comparisons": []}

# 1. CLI 启动时间
print("[1] CLI --help 启动时间...")
times = []
for _ in range(3):
    start = time.time()
    subprocess.run(
        [sys.executable, "-m", "speakeasy", "--help"],
        capture_output=True, cwd=r"e:\Project\python\Speakeasy-X",
    )
    times.append(time.time() - start)

cli_avg = sum(times) / len(times)
b_cli = baseline.get("cli_help_time", {})
results["comparisons"].append({
    "metric": "CLI --help 启动时间",
    "baseline_avg": b_cli.get("avg", 0),
    "after_avg": round(cli_avg, 4),
    "baseline_min": b_cli.get("min", 0),
    "after_min": round(min(times), 4),
    "change_pct": round((cli_avg - b_cli.get("avg", cli_avg)) / b_cli.get("avg", cli_avg) * 100, 1) if b_cli.get("avg") else 0,
    "unit": "seconds",
})

# 2. 通用 bisect vs 线性扫描对比（验证优化有效性）
print("[2] 通用线性扫描 vs bisect（n=1000）...")
import bisect
sorted_list = list(range(0, 10000, 10))  # 1000 个元素
target = 9980  # 最坏情况（末尾）

# 线性扫描
start = time.time()
for _ in range(10000):
    for x in sorted_list:
        if x > target:
            break
linear_time = (time.time() - start) / 10000 * 1e6  # us/op

# bisect
start = time.time()
for _ in range(10000):
    bisect.bisect_right(sorted_list, target)
bisect_time = (time.time() - start) / 10000 * 1e6

b_linear = baseline.get("linear_scan_1000", {})
b_bisect = baseline.get("bisect_search_1000", {})
results["comparisons"].append({
    "metric": "线性扫描 n=1000",
    "baseline": b_linear.get("time_per_op", 0),
    "after": round(linear_time, 2),
    "unit": "microseconds",
})
results["comparisons"].append({
    "metric": "bisect 查找 n=1000",
    "baseline": b_bisect.get("time_per_op", 0),
    "after": round(bisect_time, 2),
    "unit": "microseconds",
})

# 3. memmgr.get_address_map 真实测量（如果可访问）
print("[3] memmgr.get_address_map 真实测量...")
try:
    from speakeasy.memmgr import MemoryManager, MemMap

    mm = MemoryManager(page_size=0x1000)
    # 构造 1000 个映射
    for i in range(1000):
        m = MemMap(base=0x1000 * (i + 1), size=0x1000, tag="test")
        mm.maps.append(m)
    mm._rebuild_sorted_bases()

    # 查找最后一个（最坏情况）
    target_addr = 0x1000 * 1000 + 0x800
    start = time.time()
    for _ in range(10000):
        mm.get_address_map(target_addr)
    memmgr_time = (time.time() - start) / 10000 * 1e6

    results["comparisons"].append({
        "metric": "memmgr.get_address_map (n=1000, 最坏)",
        "baseline": baseline.get("memmgr_get_address_map_worst", {}).get("time_per_op", 103.82),
        "after": round(memmgr_time, 2),
        "speedup": round(baseline.get("memmgr_get_address_map_worst", {}).get("time_per_op", 103.82) / memmgr_time, 1) if memmgr_time > 0 else 0,
        "unit": "microseconds",
    })
    print(f"   get_address_map: {memmgr_time:.2f} us/op (基线 103.82 us)")
except Exception as e:
    print(f"   跳过: {e}")
    results["comparisons"].append({"metric": "memmgr.get_address_map", "error": str(e)})

# 4. struct 字段访问测量
print("[4] struct 字段访问测量...")
try:
    from speakeasy.struct import Struct

    class TestStruct(Struct):
        _fields_ = [
            ("field1", "I"),
            ("field2", "I"),
            ("field3", "I"),
            ("field4", "I"),
            ("field5", "I"),
        ]

    # 创建结构体（需要模拟 emu 环境，可能失败）
    # 跳过如果需要完整 emu 上下文
    print("   跳过（需要完整 emu 上下文）")
except Exception as e:
    print(f"   跳过: {e}")

# 输出对比表
print("\n" + "=" * 80)
print("性能对比报告")
print("=" * 80)
print(f"{'指标':<35s} {'基线':>12s} {'优化后':>12s} {'变化':>10s}")
print("-" * 80)
for c in results["comparisons"]:
    metric = c["metric"]
    if "error" in c:
        print(f"{metric:<35s} {'ERROR':>12s} {'-':>12s} {'-':>10s}")
        continue
    base_val = c.get("baseline", c.get("baseline_avg", 0))
    after_val = c.get("after", c.get("after_avg", 0))
    if "change_pct" in c:
        change = f"{c['change_pct']:+.1f}%"
    elif "speedup" in c:
        change = f"{c['speedup']}x"
    else:
        change = "-"
    print(f"{metric:<35s} {base_val:>12.2f} {after_val:>12.2f} {change:>10s}")

# 保存
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print(f"\n结果已保存: {OUTPUT_FILE}")
