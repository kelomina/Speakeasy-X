"""
Speakeasy模拟可行性验证脚本
验证模拟成功率、时间成本和报告质量
"""

import os
import sys
import json
import time
import random
from pathlib import Path
from typing import List, Dict, Any

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from speakeasy import Speakeasy


def sample_pe_files(directory: Path, count: int = 100, seed: int = 42) -> List[Path]:
    """从目录中抽取PE文件样本"""
    random.seed(seed)
    
    # 收集所有PE文件
    pe_files = []
    for ext in ['*.exe', '*.dll', '*.sys']:
        pe_files.extend(directory.rglob(ext))
    
    # 随机抽样
    if len(pe_files) <= count:
        return pe_files
    
    return random.sample(pe_files, count)


def run_simulation(sample_path: Path, timeout: int = 60) -> Dict[str, Any]:
    """运行单个样本的模拟"""
    result = {
        'path': str(sample_path),
        'success': False,
        'error': None,
        'duration': 0,
        'features': {}
    }
    
    try:
        start_time = time.time()
        
        # 创建模拟器实例
        se = Speakeasy()
        
        # 加载模块
        module = se.load_module(str(sample_path))
        
        # 运行模拟
        se.run_module(module, all_entrypoints=True)
        
        # 获取报告
        report = se.get_report()
        
        result['duration'] = time.time() - start_time
        result['success'] = True
        
        # 提取基础特征
        result['features'] = extract_features(report)
        
    except Exception as e:
        result['duration'] = time.time() - start_time
        result['error'] = str(e)
    
    return result


def extract_features(report) -> Dict[str, Any]:
    """从报告中提取基础特征（适配实际报告结构：dict格式）"""
    features = {}

    # 将report转为dict（兼容pydantic模型和dict两种情况）
    if hasattr(report, 'model_dump'):
        r = report.model_dump()
    elif isinstance(report, dict):
        r = report
    else:
        r = vars(report)

    # 基础信息
    features['file_size'] = r.get('size', 0)
    features['file_type'] = r.get('filetype', 'unknown')
    features['arch'] = r.get('arch', 'unknown')
    features['sha256'] = r.get('sha256', '')
    features['emulation_runtime'] = r.get('emulation_total_runtime', 0)

    # 入口点信息
    entry_points = r.get('entry_points', []) or []
    features['entry_point_count'] = len(entry_points)

    # API调用统计
    api_stats = {}
    total_api_calls = 0
    unique_apis = set()
    behavior_events = {}

    for ep in entry_points:
        events = ep.get('events', []) or []
        for event in events:
            event_type = event.get('event', 'unknown')
            behavior_events[event_type] = behavior_events.get(event_type, 0) + 1

            if event_type == 'api':
                api_name = event.get('api_name', '')
                if api_name:
                    # 提取DLL名称
                    dll_name = api_name.split('.')[0] if '.' in api_name else api_name
                    api_stats[dll_name] = api_stats.get(dll_name, 0) + 1
                    total_api_calls += 1
                    unique_apis.add(api_name)

    features['api_stats'] = api_stats
    features['unique_api_count'] = len(unique_apis)
    features['total_api_calls'] = total_api_calls
    features['behavior_events'] = behavior_events

    # 字符串特征
    strings = r.get('strings', None) or {}
    if isinstance(strings, dict):
        static_s = strings.get('static', {}) or {}
        in_memory = strings.get('in_memory', {}) or {}
        features['static_ansi_count'] = len(static_s.get('ansi', []))
        features['static_unicode_count'] = len(static_s.get('unicode', []))
        features['memory_ansi_count'] = len(in_memory.get('ansi', []))
        features['memory_unicode_count'] = len(in_memory.get('unicode', []))
    else:
        features['static_ansi_count'] = 0
        features['static_unicode_count'] = 0
        features['memory_ansi_count'] = 0
        features['memory_unicode_count'] = 0

    # 网络活动
    features['network_connections'] = behavior_events.get('net_dns', 0) + \
                                      behavior_events.get('net_http', 0) + \
                                      behavior_events.get('net_traffic', 0)

    # 文件操作
    features['file_operations'] = behavior_events.get('file_create', 0) + \
                                  behavior_events.get('file_write', 0) + \
                                  behavior_events.get('file_open', 0) + \
                                  behavior_events.get('file_read', 0)

    # 注册表操作
    features['registry_operations'] = behavior_events.get('reg_open_key', 0) + \
                                      behavior_events.get('reg_read_value', 0) + \
                                      behavior_events.get('reg_write_value', 0) + \
                                      behavior_events.get('reg_create_key', 0)

    # 进程/线程操作
    features['process_operations'] = behavior_events.get('process_create', 0) + \
                                     behavior_events.get('thread_create', 0) + \
                                     behavior_events.get('thread_inject', 0)

    # 内存操作
    features['memory_operations'] = behavior_events.get('mem_alloc', 0) + \
                                    behavior_events.get('mem_write', 0) + \
                                    behavior_events.get('mem_protect', 0)

    # 错误信息
    error_count = sum(1 for ep in entry_points if ep.get('error'))
    features['has_errors'] = error_count > 0
    features['error_count'] = error_count

    # 动态代码段（解包指标）
    dynamic_code_count = sum(len(ep.get('dynamic_code_segments', []) or []) for ep in entry_points)
    features['dynamic_code_segments'] = dynamic_code_count

    # 释放文件
    dropped_files_count = sum(len(ep.get('dropped_files', []) or []) for ep in entry_points)
    features['dropped_files'] = dropped_files_count

    return features


def validate_simulation(
    malicious_dir: Path,
    benign_dir: Path,
    sample_count: int = 100,
    output_dir: Path = None
):
    """验证Speakeasy模拟可行性"""
    
    if output_dir is None:
        output_dir = Path(__file__).parent / 'validation_results'
    output_dir.mkdir(exist_ok=True)
    
    print("=" * 80)
    print("Speakeasy模拟可行性验证")
    print("=" * 80)
    
    # 1. 抽样
    print(f"\n[1/3] 抽样阶段")
    print(f"从恶意样本中抽取 {sample_count} 个PE文件...")
    malicious_samples = sample_pe_files(malicious_dir, sample_count)
    print(f"实际抽取: {len(malicious_samples)} 个")
    
    print(f"从良性样本中抽取 {sample_count} 个PE文件...")
    benign_samples = sample_pe_files(benign_dir, sample_count)
    print(f"实际抽取: {len(benign_samples)} 个")
    
    # 2. 模拟测试
    print(f"\n[2/3] 模拟测试阶段")
    
    results = {
        'malicious': [],
        'benign': [],
        'summary': {}
    }
    
    # 测试恶意样本
    print(f"\n测试恶意样本 ({len(malicious_samples)} 个)...")
    for i, sample in enumerate(malicious_samples, 1):
        print(f"  [{i}/{len(malicious_samples)}] {sample.name}...", end=' ')
        result = run_simulation(sample)
        results['malicious'].append(result)
        
        if result['success']:
            print(f"✓ 成功 ({result['duration']:.2f}s)")
        else:
            print(f"✗ 失败: {result['error'][:50]}...")
    
    # 测试良性样本
    print(f"\n测试良性样本 ({len(benign_samples)} 个)...")
    for i, sample in enumerate(benign_samples, 1):
        print(f"  [{i}/{len(benign_samples)}] {sample.name}...", end=' ')
        result = run_simulation(sample)
        results['benign'].append(result)
        
        if result['success']:
            print(f"✓ 成功 ({result['duration']:.2f}s)")
        else:
            print(f"✗ 失败: {result['error'][:50]}...")
    
    # 3. 统计分析
    print(f"\n[3/3] 统计分析阶段")
    
    # 计算统计指标
    for category in ['malicious', 'benign']:
        samples = results[category]
        total = len(samples)
        success_count = sum(1 for s in samples if s['success'])
        fail_count = total - success_count
        
        success_samples = [s for s in samples if s['success']]
        if success_samples:
            avg_duration = sum(s['duration'] for s in success_samples) / len(success_samples)
            max_duration = max(s['duration'] for s in success_samples)
            min_duration = min(s['duration'] for s in success_samples)
        else:
            avg_duration = max_duration = min_duration = 0
        
        results['summary'][category] = {
            'total': total,
            'success': success_count,
            'failed': fail_count,
            'success_rate': success_count / total if total > 0 else 0,
            'avg_duration': avg_duration,
            'max_duration': max_duration,
            'min_duration': min_duration
        }
    
    # 打印统计结果
    print("\n" + "=" * 80)
    print("验证结果统计")
    print("=" * 80)
    
    for category in ['malicious', 'benign']:
        summary = results['summary'][category]
        print(f"\n{category.upper()} 样本:")
        print(f"  总数: {summary['total']}")
        print(f"  成功: {summary['success']} ({summary['success_rate']*100:.1f}%)")
        print(f"  失败: {summary['failed']}")
        if summary['success'] > 0:
            print(f"  平均耗时: {summary['avg_duration']:.2f}s")
            print(f"  最大耗时: {summary['max_duration']:.2f}s")
            print(f"  最小耗时: {summary['min_duration']:.2f}s")
    
    # 分析特征完整性
    print("\n" + "=" * 80)
    print("特征完整性分析")
    print("=" * 80)
    
    for category in ['malicious', 'benign']:
        success_samples = [s for s in results[category] if s['success']]
        if not success_samples:
            continue
        
        print(f"\n{category.upper()} 样本特征统计 (基于 {len(success_samples)} 个成功样本):")
        
        # 统计特征覆盖率
        feature_stats = {
            'has_api_stats': 0,
            'has_behavior_events': 0,
            'has_strings': 0,
            'has_network': 0,
            'has_file_ops': 0,
            'has_registry_ops': 0,
            'has_process_ops': 0,
            'has_memory_ops': 0,
            'has_errors': 0,
            'has_dynamic_code': 0,
            'has_dropped_files': 0
        }
        
        for sample in success_samples:
            features = sample['features']
            if features.get('unique_api_count', 0) > 0:
                feature_stats['has_api_stats'] += 1
            if sum(features.get('behavior_events', {}).values()) > 0:
                feature_stats['has_behavior_events'] += 1
            if (features.get('static_ansi_count', 0) + features.get('static_unicode_count', 0) +
                features.get('memory_ansi_count', 0) + features.get('memory_unicode_count', 0)) > 0:
                feature_stats['has_strings'] += 1
            if features.get('network_connections', 0) > 0:
                feature_stats['has_network'] += 1
            if features.get('file_operations', 0) > 0:
                feature_stats['has_file_ops'] += 1
            if features.get('registry_operations', 0) > 0:
                feature_stats['has_registry_ops'] += 1
            if features.get('process_operations', 0) > 0:
                feature_stats['has_process_ops'] += 1
            if features.get('memory_operations', 0) > 0:
                feature_stats['has_memory_ops'] += 1
            if features.get('has_errors', False):
                feature_stats['has_errors'] += 1
            if features.get('dynamic_code_segments', 0) > 0:
                feature_stats['has_dynamic_code'] += 1
            if features.get('dropped_files', 0) > 0:
                feature_stats['has_dropped_files'] += 1
        
        total = len(success_samples)
        for feature, count in feature_stats.items():
            print(f"  {feature}: {count}/{total} ({count/total*100:.1f}%)")
    
    # 保存结果
    output_file = output_dir / 'validation_results.json'
    
    # 转换结果为可序列化格式
    serializable_results = {
        'summary': results['summary'],
        'malicious': [
            {
                'path': r['path'],
                'success': r['success'],
                'error': r['error'],
                'duration': r['duration'],
                'features': r['features']
            }
            for r in results['malicious']
        ],
        'benign': [
            {
                'path': r['path'],
                'success': r['success'],
                'error': r['error'],
                'duration': r['duration'],
                'features': r['features']
            }
            for r in results['benign']
        ]
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(serializable_results, f, indent=2, ensure_ascii=False)
    
    print(f"\n详细结果已保存到: {output_file}")
    
    return results


if __name__ == '__main__':
    # 配置路径
    project_root = Path(__file__).parent.parent
    malicious_dir = project_root / 'data' / 'malicious_samples'
    benign_dir = project_root / 'data' / 'benign_samples'
    
    # 运行验证
    results = validate_simulation(
        malicious_dir=malicious_dir,
        benign_dir=benign_dir,
        sample_count=5  # 先用5个样本快速验证
    )
