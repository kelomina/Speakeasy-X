"""快速评估1：特征偏差分析（不需要模拟）"""
import sys
import random
from pathlib import Path
from collections import Counter
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))
from ml_engine import StaticExtractor

def collect_samples(data_dir, label, count, seed=42):
    random.seed(seed)
    base = data_dir / ('malicious_samples' if label == 'malicious' else 'benign_samples')
    samples = [str(f) for f in base.rglob('*') if f.is_file()]
    return random.sample(samples, min(count, len(samples)))

data_dir = Path(r"e:\Project\python\Speakeasy-X\data")
extractor = StaticExtractor()

for label, count in [('malicious', 2000), ('benign', 2000)]:
    samples = collect_samples(data_dir, label, count)
    print(f"\n{'='*60}")
    print(f"{label} 样本 ({len(samples)} 个)")
    print(f"{'='*60}")

    dll_count = 0
    exe_count = 0
    file_types = Counter()
    compression_ratios = []
    entropies = []
    suspicious_counts = []
    import_counts = []

    for i, fpath in enumerate(samples, 1):
        if i % 500 == 0:
            print(f"  进度: {i}/{len(samples)}", flush=True)
        f = extractor.extract(fpath)
        if f.get('is_dll'): dll_count += 1
        if f.get('is_exe'): exe_count += 1
        file_types[f.get('file_type', 'unknown')] += 1
        compression_ratios.append(f.get('compression_ratio', 0))
        entropies.append(f.get('overall_entropy', 0))
        suspicious_counts.append(f.get('suspicious_api_count', 0))
        import_counts.append(f.get('imported_function_count', 0))

    print(f"\nis_dll: {dll_count} ({dll_count/len(samples)*100:.1f}%)")
    print(f"is_exe: {exe_count} ({exe_count/len(samples)*100:.1f}%)")
    print(f"\nfile_type分布:")
    for ft, c in file_types.most_common(10):
        print(f"  {ft}: {c} ({c/len(samples)*100:.1f}%)")
    print(f"\ncompression_ratio: mean={np.mean(compression_ratios):.4f}, std={np.std(compression_ratios):.4f}")
    print(f"overall_entropy: mean={np.mean(entropies):.4f}, std={np.std(entropies):.4f}")
    print(f"suspicious_api_count: mean={np.mean(suspicious_counts):.2f}, max={max(suspicious_counts)}")
    print(f"imported_function_count: mean={np.mean(import_counts):.2f}, max={max(import_counts)}")
