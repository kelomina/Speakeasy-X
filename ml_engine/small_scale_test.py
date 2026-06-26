"""
小规模测试：验证F1分数
使用1000个恶意样本 + 1000个良性样本进行快速验证
"""

import sys
import random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml_engine import MLPipeline


def collect_samples(data_dir: Path, label: str, count: int = 1000, seed: int = 42):
    """收集样本"""
    random.seed(seed)
    samples = []

    if label == 'malicious':
        base_dir = data_dir / 'malicious_samples'
    else:
        base_dir = data_dir / 'benign_samples'

    # 递归收集所有文件
    for fpath in base_dir.rglob('*'):
        if fpath.is_file():
            samples.append(str(fpath))

    # 随机抽样
    if len(samples) > count:
        samples = random.sample(samples, count)

    return samples


def main():
    print("=" * 80)
    print("小规模测试：验证F1分数")
    print("=" * 80)

    data_dir = Path(r"e:\Project\python\Speakeasy-X\data")

    # 收集样本
    print("\n[1/4] 收集样本...")
    malicious_samples = collect_samples(data_dir, 'malicious', count=1000)
    benign_samples = collect_samples(data_dir, 'benign', count=1000)
    print(f"恶意样本: {len(malicious_samples)}")
    print(f"良性样本: {len(benign_samples)}")

    # 创建Pipeline（Flash模式，仅静态特征）
    print("\n[2/4] 创建ML Pipeline (Flash模式)...")
    pipeline = MLPipeline(mode='flash', n_clusters=10, model_type='random_forest')

    # 准备训练数据
    print("\n[3/4] 提取特征...")
    X, y = pipeline.prepare_training_data(malicious_samples, benign_samples)
    print(f"特征矩阵: {X.shape}")
    print(f"标签分布: 恶意={sum(y==1)}, 良性={sum(y==0)}")

    # 训练模型
    print("\n[4/4] 训练模型...")
    metrics = pipeline.train(X, y)

    # 打印结果
    print("\n" + "=" * 80)
    print("训练结果")
    print("=" * 80)
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall: {metrics['recall']:.4f}")
    print(f"F1 Score: {metrics['f1']:.4f}")
    print(f"Confusion Matrix:")
    for row in metrics['confusion_matrix']:
        print(f"  {row}")

    if 'cv_f1_mean' in metrics:
        print(f"\n交叉验证 F1: {metrics['cv_f1_mean']:.4f} ± {metrics['cv_f1_std']:.4f}")

    # 特征重要性 Top 10
    if 'feature_importances' in metrics:
        print("\n特征重要性 Top 10:")
        feature_names = pipeline.vectorizer.feature_names
        importances = metrics['feature_importances']
        sorted_indices = sorted(range(len(importances)), key=lambda i: importances[i], reverse=True)
        for i in range(min(10, len(sorted_indices))):
            idx = sorted_indices[i]
            print(f"  {feature_names[idx]:30s}: {importances[idx]:.4f}")

    # 对恶意样本进行聚类
    print("\n" + "=" * 80)
    print("恶意软件家族聚类")
    print("=" * 80)
    malicious_X = X[y == 1]
    family_labels = pipeline.cluster_malware_families(malicious_X)
    print(f"发现家族: {family_labels}")

    # 保存模型
    print("\n" + "=" * 80)
    print("保存模型")
    print("=" * 80)
    output_dir = Path(__file__).parent / 'models' / 'flash_v1'
    pipeline.save(str(output_dir))

    # 测试预测
    print("\n" + "=" * 80)
    print("测试预测")
    print("=" * 80)
    test_samples = [
        (malicious_samples[0], 'malicious'),
        (benign_samples[0], 'benign'),
    ]
    for fpath, expected in test_samples:
        result = pipeline.predict(fpath)
        print(f"\n文件: {Path(fpath).name}")
        print(f"  预期: {expected}")
        print(f"  预测: {result['prediction']}")
        print(f"  置信度: {result['confidence']:.4f}")

    print("\n" + "=" * 80)
    print("测试完成")
    print("=" * 80)


if __name__ == '__main__':
    main()
