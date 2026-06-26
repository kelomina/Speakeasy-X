"""快速评估Speakeasy模拟可行性：统计.NET比例和模拟成功率"""
import sys
import time
import random
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent.parent))

import pefile

def collect_samples(data_dir, label, count, seed=42):
    random.seed(seed)
    base = data_dir / ('malicious_samples' if label == 'malicious' else 'benign_samples')
    samples = [str(f) for f in base.rglob('*') if f.is_file()]
    return random.sample(samples, min(count, len(samples)))

def check_dotnet(file_path):
    """检测是否是.NET程序集"""
    try:
        pe = pefile.PE(file_path, fast_load=False)
        try:
            # .NET程序集有IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
            if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
                return True
            # 检查mscoree.dll导入
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('ascii', errors='ignore').lower()
                    if 'mscoree' in dll:
                        return True
            return False
        finally:
            pe.close()
    except Exception:
        return None  # 解析失败

data_dir = Path(r"e:\Project\python\Speakeasy-X\data")

print("=" * 80)
print("Speakeasy模拟可行性评估")
print("=" * 80)

# 1. 统计.NET比例（快速，不需要模拟）
print("\n1. .NET样本比例统计（1000样本）")
print("-" * 60)

for label in ['malicious', 'benign']:
    samples = collect_samples(data_dir, label, 500)
    dotnet_count = 0
    pe_success = 0
    pe_fail = 0

    for i, fpath in enumerate(samples, 1):
        if i % 100 == 0:
            print(f"  {label} 进度: {i}/500")
        result = check_dotnet(fpath)
        if result is None:
            pe_fail += 1
        else:
            pe_success += 1
            if result:
                dotnet_count += 1

    print(f"\n{label} 样本统计:")
    print(f"  PE解析成功: {pe_success}/{len(samples)} ({pe_success/len(samples)*100:.1f}%)")
    print(f"  PE解析失败: {pe_fail}/{len(samples)} ({pe_fail/len(samples)*100:.1f}%)")
    if pe_success > 0:
        print(f"  .NET程序集: {dotnet_count}/{pe_success} ({dotnet_count/pe_success*100:.1f}%)")
        print(f"  可模拟(非.NET): {pe_success - dotnet_count}/{pe_success} ({(pe_success - dotnet_count)/pe_success*100:.1f}%)")

# 2. 小规模实际模拟测试
print("\n\n2. 实际模拟测试（20样本）")
print("-" * 60)

from speakeasy import Speakeasy

samples = collect_samples(data_dir, 'malicious', 20)
success_count = 0
fail_count = 0
dotnet_count = 0
other_fail = 0
durations = []

error_types = Counter()

for i, fpath in enumerate(samples, 1):
    print(f"\n样本 {i}/20: {Path(fpath).name[:40]}")

    # 先检查是否.NET
    is_dotnet = check_dotnet(fpath)
    if is_dotnet:
        print(f"  跳过(.NET)")
        dotnet_count += 1
        continue

    start = time.time()
    try:
        se = Speakeasy()
        module = se.load_module(fpath)
        se.run_module(module, all_entrypoints=True)
        report = se.get_json_report()
        duration = time.time() - start
        durations.append(duration)
        success_count += 1
        print(f"  ✓ 成功 ({duration:.2f}s)")
    except Exception as e:
        duration = time.time() - start
        err_msg = str(e)[:80]
        print(f"  ✗ 失败 ({duration:.2f}s): {err_msg}")
        fail_count += 1
        if '.NET' in err_msg or 'CLR' in err_msg:
            dotnet_count += 1
        else:
            other_fail += 1
            error_types[err_msg[:50]] += 1

print("\n\n" + "=" * 80)
print("模拟可行性总结")
print("=" * 80)

total = len(samples)
print(f"\n总样本: {total}")
print(f"成功: {success_count} ({success_count/total*100:.1f}%)")
print(f".NET跳过: {dotnet_count} ({dotnet_count/total*100:.1f}%)")
print(f"其他失败: {other_fail} ({other_fail/total*100:.1f}%)")

if durations:
    print(f"\n成功样本耗时:")
    print(f"  平均: {sum(durations)/len(durations):.2f}s")
    print(f"  最小: {min(durations):.2f}s")
    print(f"  最大: {max(durations):.2f}s")

if error_types:
    print(f"\n失败原因:")
    for err, cnt in error_types.most_common():
        print(f"  {err}: {cnt}")

print("\n结论:")
coverage = (success_count + dotnet_count) / total  # 可处理 = 成功 + .NET可识别跳过
print(f"  可处理率: {coverage*100:.1f}% (成功模拟 + .NET识别)")
print(f"  Pro模式可行: {'是' if coverage > 0.7 else '部分可行'}")
print(f"  .NET需替代方案: {'是' if dotnet_count/total > 0.1 else '否'}")
