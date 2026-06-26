"""评估不同样本规模下的F1稳定性"""
import sys
import random
from pathlib import Path
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml_engine import MLPipeline

def collect_samples(data_dir, label, count, seed=42):
    random.seed(seed)
    base = data_dir / ('malicious_samples' if label == 'malicious' else 'benign_samples')
    samples = [str(f) for f in base.rglob('*') if f.is_file()]
    return random.sample(samples, min(count, len(samples)))

data_dir = Path(r"e:\Project\python\Speakeasy-X\data")

print("=" * 80)
print("大规模F1验证")
print("=" * 80)

sample_counts = [500, 1000, 2000]

for count in sample_counts:
    print(f"\n测试规模: {count} 恶意 + {count} 良性")
    
    malicious_samples = collect_samples(data_dir, 'malicious', count, seed=42)
    benign_samples = collect_samples(data_dir, 'benign', count, seed=42)
    
    pipeline = MLPipeline(mode='flash', n_clusters=10, model_type='random_forest')
    X, y = pipeline.prepare_training_data(malicious_samples, benign_samples)
    metrics = pipeline.train(X, y)
    
    print(f"  F1: {metrics['f1']:.4f}, Accuracy: {metrics['accuracy']:.4f}")
    if 'cv_f1_mean' in metrics:
        print(f"  CV F1: {metrics['cv_f1_mean']:.4f} ± {metrics['cv_f1_std']:.4f}")

print("\n" + "=" * 80)
print("评估完成")
print("=" * 80)
