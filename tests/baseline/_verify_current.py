"""交叉验收代理 I：对比 P0 优化前后的仿真行为一致性。

逻辑与 _generate_baseline.py 保持一致，便于公平对比：
- 加载 6 个测试样本，使用 tests/test.json 配置运行仿真
- 提取当前报告的事件计数与 schema
- 与 tests/baseline/counts_*.json、schema_*.json、timing_baseline.json 对比
- 输出详细的差异分析报告

运行方式（注意必须禁用 faulthandler）：
    python -m pytest -p no:faulthandler --no-header -q tests/baseline/_verify_current.py  # 不可，非测试文件
    python tests/baseline/_verify_current.py
"""

from __future__ import annotations

import copy
import json
import lzma
import sys
import time
import traceback
from pathlib import Path

from speakeasy import Speakeasy

TESTS_DIR = Path(__file__).resolve().parent.parent
BINS_DIR = TESTS_DIR / "bins"
BASELINE_DIR = Path(__file__).resolve().parent

SAMPLES = [
    "argv_test_x86.exe.xz",
    "argv_test_x64.exe.xz",
    "dll_test_x86.dll.xz",
    "seh_test_x86.exe.xz",
    "wdm_test_x86.sys.xz",
    "file_access_test_x64.exe.xz",
]

FILE_EVENTS = {"file_create", "file_write", "file_open", "file_read"}
REG_EVENTS = {"reg_open_key", "reg_read_value", "reg_write_value", "reg_list_subkeys", "reg_create_key"}
NET_EVENTS = {"net_dns", "net_traffic", "net_http"}


def load_bin(name: str) -> bytes:
    with lzma.open(BINS_DIR / name) as f:
        return f.read()


def extract_schema(obj, prefix=""):
    """与 _generate_baseline.py 中完全一致的 schema 提取逻辑。"""
    schema = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            schema[key] = type(v).__name__
            schema.update(extract_schema(v, key))
    elif isinstance(obj, list):
        schema[f"{prefix}._list_len"] = len(obj)
        if obj:
            schema.update(extract_schema(obj[0], f"{prefix}[0]"))
    return schema


def extract_counts(report):
    """与 _generate_baseline.py 中完全一致的计数提取逻辑。"""
    c = {
        "entry_points": 0, "api_calls": 0, "file_ops": 0, "registry_ops": 0,
        "network_ops": 0, "mem_alloc_events": 0, "mem_write_events": 0,
        "mem_read_events": 0, "mem_protect_events": 0, "mem_free_events": 0,
        "process_create_events": 0, "module_load_events": 0,
        "thread_create_events": 0, "thread_inject_events": 0,
        "exception_events": 0, "strings_static_ansi": 0,
        "strings_static_unicode": 0, "strings_in_memory_ansi": 0,
        "strings_in_memory_unicode": 0, "memory_regions": 0,
        "loaded_modules": 0, "dropped_files": 0,
        "dynamic_code_segments": 0, "errors_total": 0,
    }
    eps = report.get("entry_points") or []
    c["entry_points"] = len(eps)
    for ep in eps:
        for evt in ep.get("events") or []:
            kind = evt.get("event")
            if kind == "api": c["api_calls"] += 1
            elif kind in FILE_EVENTS: c["file_ops"] += 1
            elif kind in REG_EVENTS: c["registry_ops"] += 1
            elif kind in NET_EVENTS: c["network_ops"] += 1
            elif kind == "mem_alloc": c["mem_alloc_events"] += 1
            elif kind == "mem_write": c["mem_write_events"] += 1
            elif kind == "mem_read": c["mem_read_events"] += 1
            elif kind == "mem_protect": c["mem_protect_events"] += 1
            elif kind == "mem_free": c["mem_free_events"] += 1
            elif kind == "process_create": c["process_create_events"] += 1
            elif kind == "module_load": c["module_load_events"] += 1
            elif kind == "thread_create": c["thread_create_events"] += 1
            elif kind == "thread_inject": c["thread_inject_events"] += 1
            elif kind == "exception": c["exception_events"] += 1
        if ep.get("error"): c["errors_total"] += 1
        if ep.get("memory"):
            c["memory_regions"] += len(ep["memory"].get("layout") or [])
            c["loaded_modules"] += len(ep["memory"].get("modules") or [])
        if ep.get("dropped_files"): c["dropped_files"] += len(ep["dropped_files"])
        if ep.get("dynamic_code_segments"): c["dynamic_code_segments"] += len(ep["dynamic_code_segments"])
    if report.get("errors"): c["errors_total"] += len(report["errors"])
    strings = report.get("strings") or {}
    static = strings.get("static") or {}
    in_mem = strings.get("in_memory") or {}
    c["strings_static_ansi"] = len(static.get("ansi") or [])
    c["strings_static_unicode"] = len(static.get("unicode") or [])
    c["strings_in_memory_ansi"] = len(in_mem.get("ansi") or [])
    c["strings_in_memory_unicode"] = len(in_mem.get("unicode") or [])
    return c


def run_sample(config, name, data):
    se = Speakeasy(config=copy.deepcopy(config), argv=[])
    try:
        module = se.load_module(data=data, filename=name.replace(".xz", ""))
        t0 = time.perf_counter()
        se.run_module(module, all_entrypoints=True)
        elapsed = time.perf_counter() - t0
        report_json = se.get_json_report()
    finally:
        se.shutdown()
    report = json.loads(report_json)
    return {"report": report, "report_json": report_json, "elapsed": elapsed}


def diff_counts(baseline, current):
    """返回 (是否一致, 差异详情 dict)。忽略 elapsed_seconds 与 sample 字段。"""
    ignore = {"elapsed_seconds", "sample"}
    diffs = {}
    all_keys = set(baseline) | set(current)
    for k in sorted(all_keys):
        if k in ignore:
            continue
        b = baseline.get(k)
        c = current.get(k)
        if b != c:
            diffs[k] = {"baseline": b, "current": c, "delta": (c - b) if isinstance(b, int) and isinstance(c, int) else None}
    return (not diffs, diffs)


def diff_schema(baseline, current):
    """返回 (是否一致, 差异详情 dict)。
    - added: 当前有、基线无
    - removed: 基线有、当前无
    - type_changed: 类型名不同
    - list_len_changed: _list_len 数值不同
    """
    added = {}
    removed = {}
    type_changed = {}
    list_len_changed = {}
    all_keys = set(baseline) | set(current)
    for k in sorted(all_keys):
        b = baseline.get(k, None)
        c = current.get(k, None)
        if b is None and c is not None:
            added[k] = c
        elif b is not None and c is None:
            removed[k] = b
        elif b != c:
            if k.endswith("._list_len"):
                list_len_changed[k] = {"baseline": b, "current": c}
            else:
                type_changed[k] = {"baseline": b, "current": c}
    consistent = not (added or removed or type_changed or list_len_changed)
    detail = {
        "added": added,
        "removed": removed,
        "type_changed": type_changed,
        "list_len_changed": list_len_changed,
    }
    return (consistent, detail)


def main():
    with (TESTS_DIR / "test.json").open() as f:
        base_config = json.load(f)

    with (BASELINE_DIR / "timing_baseline.json").open() as f:
        timing_baseline = json.load(f)

    results = []
    print("=" * 100)
    print("交叉验收代理 I：P0 优化前后仿真行为一致性对比")
    print("=" * 100)
    print(f"{'样本':<26s} | {'状态':<6s} | {'耗时(s)':<10s} | {'基线耗时(s)':<12s} | {'eps':<5s} | {'apis':<5s} | {'files':<6s} | {'reg':<5s} | {'net':<5s} | {'exc':<5s} | {'err':<5s}")
    print("-" * 100)

    for sample in SAMPLES:
        sample_key = sample.removesuffix(".xz").rsplit(".", 1)[0]
        entry = {
            "sample": sample, "sample_key": sample_key,
            "status": "pending", "elapsed": None, "error": None,
            "counts_match": None, "counts_diff": None,
            "schema_match": None, "schema_diff": None,
            "baseline_elapsed": timing_baseline.get(sample_key, {}).get("elapsed_seconds"),
            "current_counts": None, "baseline_counts": None,
        }
        try:
            data = load_bin(sample)
        except Exception as exc:
            entry["status"] = "load_failed"
            entry["error"] = f"{type(exc).__name__}: {exc}"
            results.append(entry)
            print(f"{sample:<26s} | LOAD_FAIL | - | - | - | - | - | - | - | - | -")
            continue
        try:
            result = run_sample(base_config, sample, data)
        except Exception as exc:
            tb = traceback.format_exc(limit=6)
            entry["status"] = "run_failed"
            entry["error"] = f"{type(exc).__name__}: {exc}\n{tb}"
            results.append(entry)
            print(f"{sample:<26s} | RUN_FAIL | - | - | - | - | - | - | - | - | -")
            print(f"  ERROR: {entry['error']}")
            continue

        report = result["report"]
        elapsed = result["elapsed"]
        current_counts = extract_counts(report)
        current_schema = extract_schema(report)

        # 加载基线
        try:
            with (BASELINE_DIR / f"counts_{sample_key}.json").open() as f:
                baseline_counts = json.load(f)
        except FileNotFoundError:
            baseline_counts = {}
        try:
            with (BASELINE_DIR / f"schema_{sample_key}.json").open() as f:
                baseline_schema = json.load(f)
        except FileNotFoundError:
            baseline_schema = {}

        counts_ok, counts_diff = diff_counts(baseline_counts, current_counts)
        schema_ok, schema_diff = diff_schema(baseline_schema, current_schema)

        entry["status"] = "ok"
        entry["elapsed"] = elapsed
        entry["counts_match"] = counts_ok
        entry["counts_diff"] = counts_diff
        entry["schema_match"] = schema_ok
        entry["schema_diff"] = schema_diff
        entry["current_counts"] = current_counts
        entry["baseline_counts"] = baseline_counts
        entry["current_schema"] = current_schema
        results.append(entry)

        cc = current_counts
        print(f"{sample:<26s} | OK     | {elapsed:<10.4f} | {entry['baseline_elapsed']:<12.4f} | "
              f"{cc['entry_points']:<5d} | {cc['api_calls']:<5d} | {cc['file_ops']:<6d} | "
              f"{cc['registry_ops']:<5d} | {cc['network_ops']:<5d} | {cc['exception_events']:<5d} | "
              f"{cc['errors_total']:<5d}")

    # 详细差异输出
    print("\n" + "=" * 100)
    print("详细差异分析")
    print("=" * 100)
    for entry in results:
        sk = entry["sample_key"]
        print(f"\n--- [{sk}] ({entry['sample']}) ---")
        if entry["status"] != "ok":
            print(f"  状态: {entry['status']}")
            print(f"  错误: {entry['error']}")
            continue
        print(f"  状态: OK")
        print(f"  耗时: 当前={entry['elapsed']:.4f}s  基线={entry['baseline_elapsed']:.4f}s  "
              f"变化={((entry['elapsed'] - entry['baseline_elapsed']) / entry['baseline_elapsed'] * 100) if entry['baseline_elapsed'] else 0:+.1f}%")

        # 计数对比
        if entry["counts_match"]:
            print("  计数对比: ✅ MATCH（完全一致）")
        else:
            print("  计数对比: ⚠️  DIFF")
            for k, v in entry["counts_diff"].items():
                delta = v.get("delta")
                delta_str = f" (delta={delta:+d})" if delta is not None else ""
                print(f"    - {k}: 基线={v['baseline']}  当前={v['current']}{delta_str}")

        # Schema 对比
        sd = entry["schema_diff"]
        if entry["schema_match"]:
            print("  Schema对比: ✅ MATCH（完全一致）")
        else:
            print("  Schema对比: ⚠️  DIFF")
            if sd["added"]:
                print(f"    新增字段 ({len(sd['added'])}):")
                for k, v in sd["added"].items():
                    print(f"      + {k}: {v}")
            if sd["removed"]:
                print(f"    移除字段 ({len(sd['removed'])}):")
                for k, v in sd["removed"].items():
                    print(f"      - {k}: {v}")
            if sd["type_changed"]:
                print(f"    类型变化 ({len(sd['type_changed'])}):")
                for k, v in sd["type_changed"].items():
                    print(f"      ~ {k}: {v['baseline']} -> {v['current']}")
            if sd["list_len_changed"]:
                print(f"    列表长度变化 ({len(sd['list_len_changed'])}):")
                for k, v in sd["list_len_changed"].items():
                    print(f"      ~ {k}: {v['baseline']} -> {v['current']}")

    # 汇总表
    print("\n" + "=" * 100)
    print("汇总表")
    print("=" * 100)
    print(f"{'样本':<26s} | {'计数':<14s} | {'Schema':<10s} | {'耗时变化':<12s} | {'备注'}")
    print("-" * 100)
    summary = []
    for entry in results:
        sk = entry["sample_key"]
        if entry["status"] != "ok":
            line = f"{entry['sample']:<26s} | {entry['status']:<14s} | {'-':<10s} | {'-':<12s} | 运行失败"
            print(line)
            summary.append({"sample": sk, "counts": entry["status"], "schema": "-", "perf": "-"})
            continue
        counts_label = "MATCH" if entry["counts_match"] else "DIFF"
        schema_label = "MATCH" if entry["schema_match"] else "DIFF"
        b_elapsed = entry["baseline_elapsed"]
        c_elapsed = entry["elapsed"]
        if b_elapsed:
            pct = (c_elapsed - b_elapsed) / b_elapsed * 100
            perf_label = f"{pct:+.1f}%"
        else:
            perf_label = "-"
        note = ""
        if not entry["counts_match"]:
            note = "计数差异（需分析）"
        if not entry["schema_match"]:
            if note:
                note += "; "
            note += "schema 差异"
        line = f"{entry['sample']:<26s} | {counts_label:<14s} | {schema_label:<10s} | {perf_label:<12s} | {note}"
        print(line)
        summary.append({
            "sample": sk, "counts": counts_label, "schema": schema_label,
            "perf_pct": perf_label, "note": note,
        })

    # 保存详细结果到 JSON
    output_path = BASELINE_DIR / "_verify_current_result.json"
    serializable = []
    for entry in results:
        s = {
            "sample": entry["sample"], "sample_key": entry["sample_key"],
            "status": entry["status"], "elapsed": entry["elapsed"],
            "baseline_elapsed": entry["baseline_elapsed"],
            "counts_match": entry["counts_match"],
            "counts_diff": entry["counts_diff"],
            "schema_match": entry["schema_match"],
            "schema_diff": entry["schema_diff"],
            "current_counts": entry["current_counts"],
            "baseline_counts": entry["baseline_counts"],
        }
        if entry["error"]:
            s["error"] = entry["error"]
        serializable.append(s)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n详细结果已保存: {output_path}")

    # 最终统计
    total = len(results)
    ok_count = sum(1 for r in results if r["status"] == "ok")
    counts_match = sum(1 for r in results if r.get("counts_match"))
    schema_match = sum(1 for r in results if r.get("schema_match"))
    print(f"\n最终统计: {ok_count}/{total} 样本成功运行 | 计数一致 {counts_match}/{ok_count} | Schema一致 {schema_match}/{ok_count}")
    return 0 if ok_count == total else 1


if __name__ == "__main__":
    sys.exit(main())
