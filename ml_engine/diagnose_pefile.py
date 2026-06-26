"""诊断pefile解析问题"""
import sys
import random
from pathlib import Path
import pefile

sys.path.insert(0, str(Path(__file__).parent.parent))

def collect_samples(data_dir, label, count, seed=42):
    random.seed(seed)
    base = data_dir / ('malicious_samples' if label == 'malicious' else 'benign_samples')
    samples = [str(f) for f in base.rglob('*') if f.is_file()]
    return random.sample(samples, min(count, len(samples)))

data_dir = Path(r"e:\Project\python\Speakeasy-X\data")
samples = collect_samples(data_dir, 'malicious', 10)

print("测试pefile解析能力")
print("="*60)

for i, fpath in enumerate(samples[:5], 1):
    print(f"\n[{i}] {Path(fpath).name}")
    try:
        pe = pefile.PE(fpath, fast_load=True)
        print(f"  ✓ 成功解析")
        print(f"  Machine: {hex(pe.FILE_HEADER.Machine)}")
        print(f"  Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")
        print(f"  is_dll: {bool(pe.FILE_HEADER.Characteristics & 0x2000)}")
        print(f"  is_exe: {bool(pe.FILE_HEADER.Characteristics & 0x0002)}")
        print(f"  Sections: {len(pe.sections)}")

        # 测试导入表
        try:
            pe.parse_imports()
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                imports = pe.DIRECTORY_ENTRY_IMPORT
                print(f"  导入DLL数: {len(imports)}")
                total_funcs = sum(len(e.imports) for e in imports)
                print(f"  导入函数总数: {total_funcs}")
            else:
                print(f"  导入表: 无")
        except Exception as e:
            print(f"  导入表解析失败: {e}")

        pe.close()
    except Exception as e:
        print(f"  ✗ 解析失败: {e}")
