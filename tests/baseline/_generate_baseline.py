"""Generate the pre-optimization regression baseline.

This script is intentionally self-contained so the baseline can be regenerated
deterministically. It does **not** modify any source under ``speakeasy/``.
"""

from __future__ import annotations

import copy
import json
import lzma
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


def main():
    with (TESTS_DIR / "test.json").open() as f:
        base_config = json.load(f)
    timings = {}
    meta = {}
    for sample in SAMPLES:
        sample_key = sample.removesuffix(".xz").rsplit(".", 1)[0]
        entry = {"sample": sample, "status": "pending", "elapsed_seconds": None, "error": None}
        try:
            data = load_bin(sample)
        except Exception as exc:
            entry["status"] = "load_failed"
            entry["error"] = f"{type(exc).__name__}: {exc}"
            meta[sample_key] = entry
            print(f"[{sample}] LOAD FAILED: {entry['error']}")
            continue
        try:
            result = run_sample(base_config, sample, data)
        except Exception as exc:
            tb = traceback.format_exc(limit=4)
            entry["status"] = "run_failed"
            entry["error"] = f"{type(exc).__name__}: {exc}\n{tb}"
            meta[sample_key] = entry
            print(f"[{sample}] RUN FAILED: {entry['error']}")
            continue
        report = result["report"]
        report_json = result["report_json"]
        elapsed = result["elapsed"]
        (BASELINE_DIR / f"report_{sample_key}.json").write_text(report_json, encoding="utf-8")
        schema = extract_schema(report)
        (BASELINE_DIR / f"schema_{sample_key}.json").write_text(
            json.dumps(schema, indent=2, sort_keys=True), encoding="utf-8")
        counts = extract_counts(report)
        counts["sample"] = sample
        counts["elapsed_seconds"] = elapsed
        (BASELINE_DIR / f"counts_{sample_key}.json").write_text(
            json.dumps(counts, indent=2, sort_keys=True), encoding="utf-8")
        timings[sample_key] = {
            "sample": sample, "elapsed_seconds": elapsed,
            "entry_points": counts["entry_points"], "api_calls": counts["api_calls"],
        }
        entry["status"] = "ok"
        entry["elapsed_seconds"] = elapsed
        meta[sample_key] = entry
        print(f"[{sample}] OK elapsed={elapsed:.3f}s eps={counts['entry_points']} "
              f"apis={counts['api_calls']} files={counts['file_ops']} "
              f"reg={counts['registry_ops']} net={counts['network_ops']}")
    (BASELINE_DIR / "timing_baseline.json").write_text(
        json.dumps(timings, indent=2, sort_keys=True), encoding="utf-8")
    (BASELINE_DIR / "generation_meta.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
    ok = sum(1 for v in meta.values() if v["status"] == "ok")
    print(f"\nBaseline generation complete: {ok}/{len(SAMPLES)} samples succeeded.")


if __name__ == "__main__":
    main()
