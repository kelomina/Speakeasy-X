"""Pro模式聚类效果验证：批量模拟+行为特征聚类"""
import sys
import json
import time
import random
import multiprocessing as mp
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
import pefile
from speakeasy import Speakeasy

from ml_engine import MLPipeline, BehaviorExtractor, FeatureVectorizer


def check_dotnet(file_path):
    """检测是否是.NET程序集"""
    try:
        pe = pefile.PE(file_path, fast_load=False)
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
                return True
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('ascii', errors='ignore').lower()
                    if 'mscoree' in dll:
                        return True
            return False
        finally:
            pe.close()
    except Exception:
        return None


def _simulate_worker(file_path, queue):
    """子进程模拟worker"""
    try:
        se = Speakeasy()
        module = se.load_module(file_path)
        se.run_module(module, all_entrypoints=True)
        report = se.get_json_report()
        result = json.loads(report) if isinstance(report, str) else report
        queue.put(('success', result))
    except Exception as e:
        queue.put(('error', str(e)))


def simulate_with_timeout(file_path, timeout=20):
    """带强制超时的Speakeasy模拟（使用子进程）"""
    queue = mp.Queue()
    proc = mp.Process(target=_simulate_worker, args=(file_path, queue))
    proc.daemon = True
    proc.start()
    proc.join(timeout=timeout)

    if proc.is_alive():
        proc.terminate()
        proc.join(timeout=5)
        if proc.is_alive():
            proc.kill()
        return None

    try:
        status, result = queue.get_nowait()
        if status == 'success':
            return result
        return None
    except Exception:
        return None


def collect_samples(data_dir, label, count, seed=42):
    random.seed(seed)
    base = data_dir / ('malicious_samples' if label == 'malicious' else 'benign_samples')
    samples = [str(f) for f in base.rglob('*') if f.is_file()]
    return random.sample(samples, min(count, len(samples)))


def main():
    data_dir = Path(r"e:\Project\python\Speakeasy-X\data")
    output_dir = Path(__file__).parent / 'pro_reports'
    output_dir.mkdir(exist_ok=True)

    print("=" * 80)
    print("Pro模式聚类效果验证")
    print("=" * 80)

    # 1. 收集可模拟的恶意样本
    print("\n1. 收集可模拟样本...")
    TARGET_COUNT = 40
    malicious_samples = collect_samples(data_dir, 'malicious', 300, seed=42)

    simulatable = []
    for i, fpath in enumerate(malicious_samples, 1):
        if len(simulatable) >= TARGET_COUNT:
            break
        is_dotnet = check_dotnet(fpath)
        if is_dotnet is False:
            simulatable.append(fpath)
        if i % 50 == 0:
            print(f"  扫描 {i}, 可模拟 {len(simulatable)}")

    print(f"  找到 {len(simulatable)} 个可模拟样本")

    # 2. 批量模拟
    print(f"\n2. 批量模拟 ({len(simulatable)} 样本, 超时20s/样本)")
    reports = {}
    success_count = 0
    fail_count = 0
    start_total = time.time()

    for i, fpath in enumerate(simulatable, 1):
        sample_name = Path(fpath).stem[:30]
        print(f"  [{i}/{len(simulatable)}] {sample_name}...", end='', flush=True)

        start = time.time()
        report = simulate_with_timeout(fpath, timeout=20)
        duration = time.time() - start

        if report is not None:
            reports[fpath] = report
            success_count += 1
            print(f" OK ({duration:.1f}s)")
        else:
            fail_count += 1
            print(f" FAIL ({duration:.1f}s)")

    total_time = time.time() - start_total
    print(f"\n模拟完成: 成功={success_count}, 失败={fail_count}, 总耗时={total_time:.0f}s")

    if success_count < 10:
        print(f"\n成功样本太少({success_count})，无法有效聚类")
        return

    # 3. 提取Pro特征并聚类
    print(f"\n3. 提取Pro特征并聚类 ({success_count} 样本)")

    pipeline = MLPipeline(mode='pro', n_clusters=5, cluster_method='gmm', n_pca=15)
    behavior_extractor = BehaviorExtractor()
    vectorizer = FeatureVectorizer(mode='pro')

    X_list = []
    valid_paths = []
    print("提取特征...")
    for fpath, report in reports.items():
        try:
            features = pipeline.static_extractor.extract(fpath)
            behavior_features = behavior_extractor.extract(report)
            features.update(behavior_features)
            vector = vectorizer.vectorize(features)
            X_list.append(vector)
            valid_paths.append(fpath)
        except Exception as e:
            print(f"  特征提取失败: {e}")

    X = np.array(X_list)
    print(f"特征矩阵: {X.shape}")

    # 聚类
    print("\n聚类中...")
    family_labels = pipeline.cluster_malware_families(X)
    labels = pipeline.clusterer.model.fit_predict(pipeline.clusterer.scaler.fit_transform(X))
    if pipeline.clusterer.pca is not None:
        X_reduced = pipeline.clusterer.pca.fit_transform(pipeline.clusterer.scaler.fit_transform(X))
        labels = pipeline.clusterer.model.fit_predict(X_reduced)

    # 结果分析
    label_counter = Counter(labels)
    print(f"\n家族分布 ({len(label_counter)} 个簇):")
    for label, count in label_counter.most_common():
        family_name = family_labels.get(label, f'Cluster_{label}')
        print(f"  {family_name}: {count} 样本")

    # 轮廓系数
    from sklearn.metrics import silhouette_score
    if len(set(labels)) > 1:
        silhouette = silhouette_score(X, labels, sample_size=min(300, len(X)))
        print(f"\n轮廓系数: {silhouette:.4f}")
        if silhouette > 0.25:
            print("  聚类效果可接受")
        elif silhouette > 0:
            print("  聚类效果一般，但有改善")
        else:
            print("  聚类效果仍较差")

    # 对比Flash模式聚类
    print("\n4. 对比Flash模式聚类（相同样本）")
    flash_vectorizer = FeatureVectorizer(mode='flash')
    X_flash_list = []
    for fpath in valid_paths:
        features = pipeline.static_extractor.extract(fpath)
        X_flash_list.append(flash_vectorizer.vectorize(features))
    X_flash = np.array(X_flash_list)

    pipeline_flash = MLPipeline(mode='flash', n_clusters=5, cluster_method='gmm', n_pca=15)
    labels_flash = pipeline_flash.clusterer.fit(X_flash)
    silhouette_flash = silhouette_score(X_flash, labels_flash, sample_size=min(300, len(X_flash)))

    print(f"  Flash模式轮廓系数: {silhouette_flash:.4f}")
    print(f"  Pro模式轮廓系数:   {silhouette:.4f}")
    improvement = silhouette - silhouette_flash
    print(f"  提升: {improvement:+.4f} ({'改善' if improvement > 0 else '下降'})")

    print(f"\n  Flash特征维度: {len(flash_vectorizer.feature_names)}")
    print(f"  Pro特征维度:   {len(vectorizer.feature_names)}")

    # 保存结果
    reports_file = output_dir / 'pro_results.json'
    with open(reports_file, 'w', encoding='utf-8') as f:
        summary = {
            'sample_count': success_count,
            'feature_dim_pro': len(vectorizer.feature_names),
            'feature_dim_flash': len(flash_vectorizer.feature_names),
            'silhouette_pro': float(silhouette),
            'silhouette_flash': float(silhouette_flash),
        }
        json.dump(summary, f, indent=2)

    print(f"\n结果已保存到: {reports_file}")
    print("\n" + "=" * 80)
    print("验证完成")
    print("=" * 80)


if __name__ == '__main__':
    main()
