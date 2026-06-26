"""
数据调研脚本：统计样本的文件类型、大小分布
优化版：只统计扩展名和文件大小，不读取文件内容
"""

import os
import sys
import time
from pathlib import Path
from collections import Counter

def analyze_directory(dirpath, label):
    """分析目录中的样本"""
    print(f"\n{'='*60}")
    print(f"分析目录: {label}")
    print(f"路径: {dirpath}")
    print(f"{'='*60}")

    ext_counter = Counter()
    size_list = []
    error_count = 0
    total_count = 0

    for root, dirs, files in os.walk(dirpath):
        for fname in files:
            fpath = os.path.join(root, fname)
            total_count += 1

            # 文件大小
            try:
                fsize = os.path.getsize(fpath)
                size_list.append(fsize)
            except Exception:
                error_count += 1
                continue

            # 扩展名
            ext = os.path.splitext(fname)[1].lower()
            if ext:
                ext_counter[ext] += 1
            else:
                ext_counter["(no_ext)"] += 1

            if total_count % 50000 == 0:
                print(f"  已扫描 {total_count} 个文件...")

    print(f"\n总文件数: {total_count}")
    print(f"读取错误: {error_count}")

    # 扩展名分布
    print(f"\n扩展名分布 (Top 20):")
    for ext, count in ext_counter.most_common(20):
        pct = count / total_count * 100
        print(f"  {ext:15s}: {count:8d} ({pct:5.1f}%)")

    # 文件大小分布
    if size_list:
        size_list.sort()
        print(f"\n文件大小分布:")
        print(f"  最小: {size_list[0]:,} bytes")
        print(f"  最大: {size_list[-1]:,} bytes")
        print(f"  中位数: {size_list[len(size_list)//2]:,} bytes")
        print(f"  平均值: {sum(size_list)//len(size_list):,} bytes")

        # 分桶统计
        buckets = [
            ("< 1KB", 0, 1024),
            ("1KB-10KB", 1024, 10240),
            ("10KB-100KB", 10240, 102400),
            ("100KB-1MB", 102400, 1048576),
            ("1MB-10MB", 1048576, 10485760),
            ("10MB-100MB", 10485760, 104857600),
            ("> 100MB", 104857600, float("inf")),
        ]
        print(f"\n文件大小分桶:")
        for label_b, low, high in buckets:
            count = sum(1 for s in size_list if low <= s < high)
            pct = count / len(size_list) * 100
            print(f"  {label_b:15s}: {count:8d} ({pct:5.1f}%)")

    return {
        "total": total_count,
        "ext_counter": ext_counter,
        "size_list": size_list,
    }


if __name__ == "__main__":
    base = Path(r"e:\Project\python\Speakeasy-X\data")
    mal_dir = base / "malicious_samples"
    ben_dir = base / "benign_samples"

    print("Speakeasy-X 数据调研")
    print(f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    mal_stats = analyze_directory(mal_dir, "恶意样本")
    ben_stats = analyze_directory(ben_dir, "良性样本")

    print(f"\n{'='*60}")
    print(f"汇总")
    print(f"{'='*60}")
    print(f"恶意样本: {mal_stats['total']:,}")
    print(f"良性样本: {ben_stats['total']:,}")
    print(f"总计: {mal_stats['total'] + ben_stats['total']:,}")
