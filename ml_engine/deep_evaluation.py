"""
深度评估脚本：
1. 特征偏差分析
2. 模拟覆盖率统计
3. 大规模F1验证
4. Flash延迟测试
5. 聚类效果评估
"""

import sys
import time
import random
import json
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
from ml_engine import MLPipeline, StaticExtractor


def collect_samples(data_dir: Path, label: str, count: int = None, seed: int = 42):
    """收集样本"""
    random.seed(seed)
    samples = []
    
    if label == 'malicious':
        base_dir = data_dir / 'malicious_samples'
    else:
        base_dir = data_dir / 'benign_samples'
    
    for fpath in base_dir.rglob('*'):
        if fpath.is_file():
            samples.append(str(fpath))
    
    if count and len(samples) > count:
        samples = random.sample(samples, count)
    
    return samples


def evaluate_feature_bias(data_dir: Path, sample_count: int = 2000):
    """评估特征偏差：分析is_dll等关键特征的分布"""
    print("=" * 80)
    print("1. 特征偏差分析")
    print("=" * 80)
    
    extractor = StaticExtractor()
    
    malicious_samples = collect_samples(data_dir, 'malicious', sample_count)
    benign_samples = collect_samples(data_dir, 'benign', sample_count)
    
    print(f"\n样本数量: 恶意={len(malicious_samples)}, 良性={len(benign_samples)}")
    
    # 统计is_dll分布
    mal_dll_count = 0
    ben_dll_count = 0
    
    # 统计file_type分布
    mal_file_types = Counter()
    ben_file_types = Counter()
    
    # 统计compression_ratio分布
    mal_compression_ratios = []
    ben_compression_ratios = []
    
    print("\n提取恶意样本特征...")
    for i, fpath in enumerate(malicious_samples, 1):
        if i % 500 == 0:
            print(f"  进度: {i}/{len(malicious_samples)}")
        features = extractor.extract(fpath)
        if features.get('is_dll'):
            mal_dll_count += 1
        mal_file_types[features.get('file_type', 'unknown')] += 1
        mal_compression_ratios.append(features.get('compression_ratio', 0))
    
    print("\n提取良性样本特征...")
    for i, fpath in enumerate(benign_samples, 1):
        if i % 500 == 0:
            print(f"  进度: {i}/{len(benign_samples)}")
        features = extractor.extract(fpath)
        if features.get('is_dll'):
            ben_dll_count += 1
        ben_file_types[features.get('file_type', 'unknown')] += 1
        ben_compression_ratios.append(features.get('compression_ratio', 0))
    
    # 打印结果
    print("\n" + "-" * 80)
    print("is_dll特征分布:")
    print(f"  恶意样本: {mal_dll_count}/{len(malicious_samples)} ({mal_dll_count/len(malicious_samples)*100:.1f}%)")
    print(f"  良性样本: {ben_dll_count}/{len(benign_samples)} ({ben_dll_count/len(benign_samples)*100:.1f}%)")
    
    print("\nfile_type分布:")
    print("  恶意样本:")
    for ft, count in mal_file_types.most_common(10):
        print(f"    {ft}: {count} ({count/len(malicious_samples)*100:.1f}%)")
    print("  良性样本:")
    for ft, count in ben_file_types.most_common(10):
        print(f"    {ft}: {count} ({count/len(benign_samples)*100:.1f}%)")
    
    print("\ncompression_ratio分布:")
    if mal_compression_ratios:
        print(f"  恶意样本: mean={np.mean(mal_compression_ratios):.4f}, std={np.std(mal_compression_ratios):.4f}")
    if ben_compression_ratios:
        print(f"  良性样本: mean={np.mean(ben_compression_ratios):.4f}, std={np.std(ben_compression_ratios):.4f}")
    
    # 判断是否存在偏差
    mal_dll_ratio = mal_dll_count / len(malicious_samples)
    ben_dll_ratio = ben_dll_count / len(benign_samples)
    
    if abs(mal_dll_ratio - ben_dll_ratio) > 0.2:
        print(f"\n⚠️ 警告: is_dll特征存在显著偏差 ({mal_dll_ratio:.2f} vs {ben_dll_ratio:.2f})")
        print("   建议: 检查数据集是否平衡，或考虑移除该特征")
    else:
        print(f"\n✓ is_dll特征分布相对平衡")


def evaluate_simulation_coverage(data_dir: Path, sample_count: int = 100):
    """评估模拟覆盖率：统计.NET样本比例"""
    print("\n" + "=" * 80)
    print("2. 模拟覆盖率评估")
    print("=" * 80)
    
    from speakeasy import Speakeasy
    
    malicious_samples = collect_samples(data_dir, 'malicious', sample_count)
    
    print(f"\n测试样本: {len(malicious_samples)} 个恶意样本")
    
    success_count = 0
    dotnet_count = 0
    other_error_count = 0
    
    error_types = Counter()
    
    for i, fpath in enumerate(malicious_samples, 1):
        if i % 20 == 0:
            print(f"  进度: {i}/{len(malicious_samples)}")
        
        try:
            se = Speakeasy()
            module = se.load_module(fpath)
            se.run_module(module, all_entrypoints=True)
            success_count += 1
        except Exception as e:
            error_msg = str(e)
            if '.NET' in error_msg or 'CLR' in error_msg:
                dotnet_count += 1
                error_types['.NET'] += 1
            else:
                other_error_count += 1
                error_types[error_msg[:50]] += 1
    
    print("\n" + "-" * 80)
    print("模拟结果统计:")
    print(f"  成功: {success_count}/{len(malicious_samples)} ({success_count/len(malicious_samples)*100:.1f}%)")
    print(f"  .NET失败: {dotnet_count}/{len(malicious_samples)} ({dotnet_count/len(malicious_samples)*100:.1f}%)")
    print(f"  其他错误: {other_error_count}/{len(malicious_samples)} ({other_error_count/len(malicious_samples)*100:.1f}%)")
    
    print("\n错误类型分布:")
    for err, count in error_types.most_common(10):
        print(f"  {err}: {count}")
    
    coverage = success_count / len(malicious_samples)
    if coverage < 0.5:
        print(f"\n⚠️ 警告: 模拟覆盖率较低 ({coverage*100:.1f}%)")
        print("   建议: Pro模式可能无法覆盖足够样本，考虑增强Flash模式")
    else:
        print(f"\n✓ 模拟覆盖率可接受 ({coverage*100:.1f}%)")


def evaluate_scale_f1(data_dir: Path, sample_counts: list = [500, 1000, 2000, 5000]):
    """评估不同规模下的F1稳定性"""
    print("\n" + "=" * 80)
    print("3. 大规模F1验证")
    print("=" * 80)
    
    results = []
    
    for count in sample_counts:
        print(f"\n测试规模: {count} 恶意 + {count} 良性")
        
        malicious_samples = collect_samples(data_dir, 'malicious', count, seed=42)
        benign_samples = collect_samples(data_dir, 'benign', count, seed=42)
        
        pipeline = MLPipeline(mode='flash', n_clusters=10, model_type='random_forest')
        X, y = pipeline.prepare_training_data(malicious_samples, benign_samples)
        metrics = pipeline.train(X, y)
        
        results.append({
            'sample_count': count,
            'f1': metrics['f1'],
            'accuracy': metrics['accuracy'],
            'precision': metrics['precision'],
            'recall': metrics['recall'],
            'cv_f1_mean': metrics.get('cv_f1_mean', 0),
            'cv_f1_std': metrics.get('cv_f1_std', 0)
        })
        
        print(f"  F1: {metrics['f1']:.4f}, Accuracy: {metrics['accuracy']:.4f}")
        if 'cv_f1_mean' in metrics:
            print(f"  CV F1: {metrics['cv_f1_mean']:.4f} ± {metrics['cv_f1_std']:.4f}")
    
    print("\n" + "-" * 80)
    print("F1稳定性分析:")
    f1_scores = [r['f1'] for r in results]
    f1_variance = np.var(f1_scores)
    print(f"  F1方差: {f1_variance:.6f}")
    
    if f1_variance < 0.001:
        print("  ✓ F1非常稳定")
    elif f1_variance < 0.01:
        print("  ✓ F1较为稳定")
    else:
        print("  ⚠️ F1波动较大，可能需要更多数据或调整模型")


def evaluate_flash_latency(data_dir: Path, sample_count: int = 100):
    """评估Flash模式延迟"""
    print("\n" + "=" * 80)
    print("4. Flash模式延迟测试")
    print("=" * 80)
    
    pipeline = MLPipeline.load(str(Path(__file__).parent / 'models' / 'flash_v1'), mode='flash')
    
    malicious_samples = collect_samples(data_dir, 'malicious', sample_count // 2)
    benign_samples = collect_samples(data_dir, 'benign', sample_count // 2)
    
    all_samples = malicious_samples + benign_samples
    
    latencies = []
    
    print(f"\n测试样本: {len(all_samples)} 个")
    
    for i, fpath in enumerate(all_samples, 1):
        if i % 20 == 0:
            print(f"  进度: {i}/{len(all_samples)}")
        
        start = time.time()
        result = pipeline.predict(fpath)
        latency = time.time() - start
        latencies.append(latency)
    
    print("\n" + "-" * 80)
    print("延迟统计:")
    print(f"  平均: {np.mean(latencies)*1000:.2f} ms")
    print(f"  中位数: {np.median(latencies)*1000:.2f} ms")
    print(f"  P95: {np.percentile(latencies, 95)*1000:.2f} ms")
    print(f"  P99: {np.percentile(latencies, 99)*1000:.2f} ms")
    print(f"  最大: {np.max(latencies)*1000:.2f} ms")
    
    p95_latency = np.percentile(latencies, 95)
    if p95_latency < 1.0:
        print(f"\n✓ Flash模式满足<1秒要求 (P95={p95_latency*1000:.2f}ms)")
    else:
        print(f"\n⚠️ Flash模式延迟超标 (P95={p95_latency*1000:.2f}ms)")


def evaluate_clustering(data_dir: Path, sample_count: int = 1000):
    """评估聚类效果"""
    print("\n" + "=" * 80)
    print("5. 聚类效果评估")
    print("=" * 80)
    
    pipeline = MLPipeline(mode='flash', n_clusters=10, model_type='random_forest')
    
    malicious_samples = collect_samples(data_dir, 'malicious', sample_count)
    
    print(f"\n样本数量: {len(malicious_samples)}")
    
    # 提取特征
    X_list = []
    for i, fpath in enumerate(malicious_samples, 1):
        if i % 200 == 0:
            print(f"  进度: {i}/{len(malicious_samples)}")
        features = pipeline.static_extractor.extract(fpath)
        vector = pipeline.vectorizer.vectorize(features)
        X_list.append(vector)
    
    X = np.array(X_list)
    
    # 聚类
    family_labels = pipeline.cluster_malware_families(X)
    
    # 统计每个家族的样本数
    labels = pipeline.clusterer.model.labels_
    label_counter = Counter(labels)
    
    print("\n" + "-" * 80)
    print("家族分布:")
    for label, count in label_counter.most_common():
        family_name = family_labels.get(label, 'Unknown')
        print(f"  {family_name}: {count} 样本")
    
    # 计算轮廓系数（聚类质量指标）
    from sklearn.metrics import silhouette_score
    silhouette = silhouette_score(X, labels)
    
    print(f"\n聚类质量指标:")
    print(f"  轮廓系数: {silhouette:.4f}")
    
    if silhouette > 0.5:
        print("  ✓ 聚类效果很好")
    elif silhouette > 0.25:
        print("  ✓ 聚类效果可接受")
    else:
        print("  ⚠️ 聚类效果较差，可能需要调整特征或聚类参数")


def main():
    print("=" * 80)
    print("ML引擎深度评估")
    print("=" * 80)
    
    data_dir = Path(r"e:\Project\python\Speakeasy-X\data")
    
    # 1. 特征偏差分析
    evaluate_feature_bias(data_dir, sample_count=2000)
    
    # 2. 模拟覆盖率评估
    evaluate_simulation_coverage(data_dir, sample_count=100)
    
    # 3. 大规模F1验证
    evaluate_scale_f1(data_dir, sample_counts=[500, 1000, 2000])
    
    # 4. Flash延迟测试
    evaluate_flash_latency(data_dir, sample_count=100)
    
    # 5. 聚类效果评估
    evaluate_clustering(data_dir, sample_count=1000)
    
    print("\n" + "=" * 80)
    print("评估完成")
    print("=" * 80)


if __name__ == '__main__':
    main()
