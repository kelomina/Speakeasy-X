"""
验证 .NET 样本检测效果：对比 Flash v2（无 .NET 特征）vs Flash v3（含 .NET 特征）

优化版：用 pefile fast_load 快速判断 .NET，避免对每个文件都做完整特征提取
"""
import random
from pathlib import Path
import numpy as np
import pefile

from ml_engine.feature_extractor import StaticExtractor
from ml_engine.ml_pipeline import MLPipeline


def is_dotnet_fast(file_path):
    """
    快速判断是否 .NET 程序集：直接读 PE 头的 COM Descriptor 目录项
    （OptionalHeader.DataDirectory[14]，RVA != 0 即 .NET）
    比 pefile.PE(fast_load=True) 更快，因为只读前 1KB 文件头
    """
    try:
        with open(file_path, 'rb') as f:
            header = f.read(1024)
        if len(header) < 0x80 or header[:2] != b'MZ':
            return False
        # e_lfanew at offset 0x3C
        e_lfanew = int.from_bytes(header[0x3C:0x40], 'little')
        if e_lfanew + 0x108 > len(header):
            # 需要读更多
            with open(file_path, 'rb') as f:
                f.seek(e_lfanew)
                header = f.read(0x200)
        # PE signature + COFF header + OptionalHeader magic
        if header[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            return False
        opt_magic = int.from_bytes(header[e_lfanew+0x18:e_lfanew+0x1A], 'little')
        # PE32: 0x10B, PE32+: 0x20B
        if opt_magic == 0x10B:
            # PE32: OptionalHeader at e_lfanew+0x18, DataDirectory at offset 0x60
            # COM Descriptor (index 14) = 0x60 + 14*8 = 0xD0 in OptionalHeader
            dd_offset = e_lfanew + 0x18 + 0x60 + 14 * 8
        elif opt_magic == 0x20B:
            # PE32+: OptionalHeader at e_lfanew+0x18, DataDirectory at offset 0x70
            # COM Descriptor (index 14) = 0x70 + 14*8 = 0xE0 in OptionalHeader
            dd_offset = e_lfanew + 0x18 + 0x70 + 14 * 8
        else:
            return False
        if dd_offset + 4 > len(header):
            return False
        rva = int.from_bytes(header[dd_offset:dd_offset+4], 'little')
        return rva != 0
    except Exception:
        return False


def collect_samples_by_type(base_dir, count, want_dotnet, seed=42, max_scan=3000):
    """收集样本（按 .NET / 原生 PE 分类），限制扫描数量"""
    random.seed(seed)
    all_files = [str(f) for f in Path(base_dir).rglob('*') if f.is_file()]
    random.shuffle(all_files)
    # 只扫描前 max_scan 个文件，避免遍历全部 26 万
    scan_list = all_files[:max_scan]

    result = []
    scanned = 0
    for f in scan_list:
        scanned += 1
        if len(result) >= count:
            break
        if is_dotnet_fast(f) == want_dotnet:
            result.append(f)
    return result, scanned


def evaluate_model(model_dir, test_files, true_labels):
    """评估模型在测试集上的表现"""
    pipeline = MLPipeline.load(model_dir, mode='flash')
    extractor = StaticExtractor()

    features = []
    valid_labels = []
    for f, label in zip(test_files, true_labels):
        try:
            feat = extractor.extract(f)
            features.append(feat)
            valid_labels.append(label)
        except Exception:
            continue

    # v2 vectorizer 忽略 dotnet_ 特征，v3 包含
    X = pipeline.vectorizer.vectorize_batch(features)
    y_true = np.array(valid_labels)
    y_pred = pipeline.classifier.predict(X)
    y_proba = pipeline.classifier.predict_proba(X)

    accuracy = float((y_pred == y_true).mean())
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    confidence = float(np.mean([y_proba[i, y_pred[i]] for i in range(len(y_pred))]))

    return {
        'accuracy': accuracy, 'precision': precision, 'recall': recall, 'f1': f1,
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'confidence': confidence, 'count': len(y_true),
    }


def main():
    data_dir = Path(r'e:\Project\python\Speakeasy-X\data')
    mal_dir = data_dir / 'malicious_samples'
    ben_dir = data_dir / 'benign_samples'

    print("=" * 70)
    print(".NET 样本检测效果验证（Flash v2 vs v3）")
    print("=" * 70)

    # 快速收集测试集
    print("\n[1] 收集 .NET 恶意样本 (50)...")
    mal_dotnet, scanned = collect_samples_by_type(mal_dir, 50, want_dotnet=True)
    print(f"    找到 {len(mal_dotnet)} 个 (扫描 {scanned} 个文件)")

    print("[2] 收集 .NET 良性样本 (50)...")
    ben_dotnet, scanned = collect_samples_by_type(ben_dir, 50, want_dotnet=True)
    print(f"    找到 {len(ben_dotnet)} 个 (扫描 {scanned} 个文件)")

    print("[3] 收集原生 PE 恶意样本 (50)...")
    mal_native, scanned = collect_samples_by_type(mal_dir, 50, want_dotnet=False)
    print(f"    找到 {len(mal_native)} 个 (扫描 {scanned} 个文件)")

    print("[4] 收集原生 PE 良性样本 (50)...")
    ben_native, scanned = collect_samples_by_type(ben_dir, 50, want_dotnet=False)
    print(f"    找到 {len(ben_native)} 个 (扫描 {scanned} 个文件)")

    groups = {
        '.NET 样本': (mal_dotnet + ben_dotnet, [1]*len(mal_dotnet) + [0]*len(ben_dotnet)),
        '原生 PE 样本': (mal_native + ben_native, [1]*len(mal_native) + [0]*len(ben_native)),
        '全部样本': (
            mal_dotnet + ben_dotnet + mal_native + ben_native,
            [1]*len(mal_dotnet) + [0]*len(ben_dotnet) + [1]*len(mal_native) + [0]*len(ben_native)
        ),
    }

    models = {
        'Flash v2 (无.NET)': 'ml_engine/models/flash_v2',
        'Flash v3 (含.NET)': 'ml_engine/models/flash_v3',
    }

    print("\n" + "=" * 70)
    print("评估结果对比")
    print("=" * 70)

    for group_name, (files, labels) in groups.items():
        print(f"\n[{group_name}] n={len(files)}")
        print(f"  {'模型':<22s} {'F1':>7s} {'Acc':>7s} {'Prec':>7s} {'Rec':>7s} {'漏报':>5s} {'误报':>5s} {'置信':>7s}")
        print("  " + "-" * 80)

        for model_name, model_dir in models.items():
            try:
                m = evaluate_model(model_dir, files, labels)
                print(f"  {model_name:<22s} {m['f1']:>7.4f} {m['accuracy']:>7.4f} "
                      f"{m['precision']:>7.4f} {m['recall']:>7.4f} "
                      f"{m['fn']:>5d} {m['fp']:>5d} {m['confidence']:>7.4f}")
            except Exception as e:
                print(f"  {model_name:<22s} 错误: {e}")


if __name__ == '__main__':
    main()
