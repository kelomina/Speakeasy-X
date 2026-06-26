"""调试脚本：打印单个样本的完整报告结构"""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from speakeasy import Speakeasy

# 用一个已知能成功模拟的样本
sample_path = r"e:\Project\python\Speakeasy-X\data\benign_samples\待加入白名单\ac329f34b0f8350f635fb5818227eefed9e94204937b802c7fd0963ec8b4b99e.exe"

se = Speakeasy()
module = se.load_module(sample_path)
se.run_module(module, all_entrypoints=True)
report = se.get_report()

# 打印报告类型和所有属性
print("Report type:", type(report))
print("Report dir:", [x for x in dir(report) if not x.startswith('_')])
print()

# 尝试序列化报告
try:
    report_dict = report.model_dump()
    # 只打印顶层key和类型
    for k, v in report_dict.items():
        if isinstance(v, list):
            print(f"  {k}: list[{len(v)}]")
            if v:
                print(f"    [0] type={type(v[0])}")
                if isinstance(v[0], dict):
                    print(f"    [0] keys={list(v[0].keys())}")
        elif isinstance(v, dict):
            print(f"  {k}: dict keys={list(v.keys())}")
        elif isinstance(v, str) and len(v) > 200:
            print(f"  {k}: str(len={len(v)})")
        else:
            print(f"  {k}: {type(v).__name__} = {v}")
except Exception as e:
    print(f"model_dump failed: {e}")
    # 手动检查属性
    for attr in dir(report):
        if attr.startswith('_'):
            continue
        try:
            val = getattr(report, attr)
            if callable(val):
                continue
            print(f"  {attr}: {type(val).__name__}")
        except Exception as e2:
            print(f"  {attr}: ERROR {e2}")

# 保存完整JSON
try:
    report_json = report.model_dump_json(indent=2)
    # 截断过长的字符串
    if len(report_json) > 50000:
        report_json = report_json[:50000] + "\n... (truncated)"
    output_path = Path(__file__).parent / 'debug_report.json'
    output_path.write_text(report_json, encoding='utf-8')
    print(f"\n完整报告已保存到: {output_path}")
except Exception as e:
    print(f"保存JSON失败: {e}")
