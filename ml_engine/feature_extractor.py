"""
特征提取器：从PE文件和Speakeasy报告中提取ML特征
- StaticExtractor: 纯静态特征（Flash模式，<1秒）
- BehaviorExtractor: 模拟行为特征（Pro模式）
- CombinedExtractor: 静态+行为组合特征
"""

import os
import struct
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional
from collections import Counter

import numpy as np

try:
    import pefile
except ImportError:
    pefile = None

from .dotnet_extractor import DotNetExtractor


# ============================================================
# 静态特征提取（Flash模式，不需要模拟）
# ============================================================

class StaticExtractor:
    """从PE文件中提取静态特征，无需模拟执行"""

    # .NET 元数据提取器（方案 B：dnfile 解析 .NET 程序集）
    _dotnet_extractor = DotNetExtractor()

    # 常见DLL导入 - 用于特征化
    COMMON_DLLS = {
        'kernel32', 'user32', 'advapi32', 'shell32', 'ole32', 'oleaut32',
        'ntdll', 'ws2_32', 'wininet', 'urlmon', 'crypt32', 'advpack',
        'msvcrt', 'mscoree', 'comctl32', 'gdi32', 'comdlg32', 'winhttp',
        'shlwapi', 'psapi', 'secur32', 'bcrypt', 'ncrypt', 'crypt32',
        'netapi32', 'rpcrt4', 'imm32', 'winmm', 'wldap32',
    }

    # 高风险API - 恶意软件常用
    SUSPICIOUS_APIS = {
        'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
        'WriteProcessMemory', 'ReadProcessMemory', 'CreateRemoteThread',
        'OpenProcess', 'CreateProcess', 'WinExec', 'ShellExecute',
        'LoadLibrary', 'GetProcAddress', 'IsDebuggerPresent',
        'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
        'InternetOpen', 'InternetOpenUrl', 'HttpOpenRequest', 'HttpSendRequest',
        'URLDownloadToFile', 'WSAStartup', 'connect', 'send', 'recv',
        'RegOpenKey', 'RegSetValue', 'RegCreateKey',
        'CreateFile', 'WriteFile', 'DeleteFile',
        'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey',
        'AdjustTokenPrivileges', 'LookupPrivilegeValue',
        'CreateService', 'StartService',
    }

    # 高风险API按类别分组 - 用于家族区分
    SUSPICIOUS_API_CATEGORIES = {
        'injection': {'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
                      'WriteProcessMemory', 'ReadProcessMemory', 'CreateRemoteThread'},
        'process': {'OpenProcess', 'CreateProcess', 'WinExec', 'ShellExecute'},
        'loader': {'LoadLibrary', 'GetProcAddress'},
        'antidebug': {'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'},
        'network': {'InternetOpen', 'InternetOpenUrl', 'HttpOpenRequest', 'HttpSendRequest',
                    'URLDownloadToFile', 'WSAStartup', 'connect', 'send', 'recv'},
        'registry': {'RegOpenKey', 'RegSetValue', 'RegCreateKey'},
        'file': {'CreateFile', 'WriteFile', 'DeleteFile'},
        'crypto': {'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey'},
        'privilege': {'AdjustTokenPrivileges', 'LookupPrivilegeValue'},
        'service': {'CreateService', 'StartService'},
    }

    def extract(self, file_path: str) -> Dict[str, Any]:
        """提取PE文件的静态特征"""
        features = {}

        # 基础文件信息
        file_size = os.path.getsize(file_path)
        features['file_size'] = file_size
        features['file_size_log'] = np.log1p(file_size)

        # 计算hash
        features['sha256'] = self._compute_hash(file_path)

        if pefile is None:
            return self._fallback_features(file_path, features)

        try:
            pe = pefile.PE(file_path, fast_load=False)
        except Exception:
            return self._fallback_features(file_path, features)

        try:
            # PE基础信息
            features['is_pe'] = True
            features['machine'] = pe.FILE_HEADER.Machine
            features['is_dll'] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
            features['is_exe'] = bool(pe.FILE_HEADER.Characteristics & 0x0002)
            features['file_type'] = 'dll' if features['is_dll'] else 'exe'
            features['num_sections'] = len(pe.sections)
            features['timestamp'] = pe.FILE_HEADER.TimeDateStamp

            # 节区特征
            section_features = self._extract_section_features(pe)
            features.update(section_features)

            # 导入表特征
            import_features = self._extract_import_features(pe)
            features.update(import_features)

            # 熵值特征
            features['overall_entropy'] = self._compute_file_entropy(file_path)

            # 资源特征
            features['has_resources'] = hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE')
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                features['resource_count'] = len(pe.DIRECTORY_ENTRY_RESOURCE.entries)
            else:
                features['resource_count'] = 0

            # 调试信息
            features['has_debug'] = hasattr(pe, 'DIRECTORY_ENTRY_DEBUG')

            # TLS回调（常用于反调试）
            features['has_tls'] = hasattr(pe, 'DIRECTORY_ENTRY_TLS')

        except Exception:
            pass
        finally:
            pe.close()

        # .NET 元数据特征（方案 B：dnfile 解析 .NET 程序集）
        # 对 .NET 样本补充 P/Invoke API 类别、用户字符串等行为指示器
        try:
            dotnet_features = self._dotnet_extractor.extract(file_path)
            features.update(dotnet_features)
        except Exception:
            features.update(self._dotnet_extractor._default_features())

        return features

    def _extract_section_features(self, pe) -> Dict[str, Any]:
        """提取节区特征"""
        features = {}
        section_names = []
        total_raw_size = 0
        total_virtual_size = 0
        section_entropies = []
        executable_sections = 0
        writable_sections = 0
        suspicious_section_count = 0

        # 可疑节区名（加壳/混淆特征）
        suspicious_section_names = {
            '.upx0', '.upx1', '.upx2', '.aspack', '.adata', '.nsp0', '.nsp1',
            '.nsp2', '.pebundle', '.mpress1', '.mpress2', '.themida', '.winlice',
            '.vmp0', '.vmp1', '.vmp2', '.svkp', '.petite', '.yod', '.pecompact',
        }

        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode('ascii', errors='ignore')
            section_names.append(name)
            total_raw_size += section.SizeOfRawData
            total_virtual_size += section.Misc_VirtualSize

            # 节区熵
            try:
                if section.SizeOfRawData > 0:
                    data = section.get_data()
                    section_entropies.append(self._compute_entropy_bytes(data))
                else:
                    section_entropies.append(0.0)
            except Exception:
                section_entropies.append(0.0)

            # 节区属性
            try:
                if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    executable_sections += 1
                if section.Characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
                    writable_sections += 1
            except Exception:
                pass

            # 检测可疑节区名
            if name.lower() in suspicious_section_names:
                suspicious_section_count += 1

        features['section_names'] = '|'.join(section_names[:10])
        features['total_raw_size'] = total_raw_size
        features['total_virtual_size'] = total_virtual_size
        # 压缩比：raw/virtual < 1 表示可能被压缩
        if total_virtual_size > 0:
            features['compression_ratio'] = total_raw_size / total_virtual_size
        else:
            features['compression_ratio'] = 0

        features['has_packer_section'] = 1 if suspicious_section_count > 0 else 0
        features['suspicious_section_count'] = suspicious_section_count
        features['executable_section_count'] = executable_sections
        features['writable_section_count'] = writable_sections

        # 节区熵统计
        if section_entropies:
            features['section_entropy_mean'] = float(np.mean(section_entropies))
            features['section_entropy_max'] = float(np.max(section_entropies))
            features['section_entropy_min'] = float(np.min(section_entropies))
            features['section_entropy_std'] = float(np.std(section_entropies))
            # 高熵节区数量（>7.0可能加壳）
            features['high_entropy_sections'] = sum(1 for e in section_entropies if e > 7.0)
        else:
            features['section_entropy_mean'] = 0.0
            features['section_entropy_max'] = 0.0
            features['section_entropy_min'] = 0.0
            features['section_entropy_std'] = 0.0
            features['high_entropy_sections'] = 0

        return features

    def _extract_import_features(self, pe) -> Dict[str, Any]:
        """提取导入表特征"""
        features = {}
        imported_dlls = set()
        imported_functions = []
        suspicious_count = 0
        # 按类别统计高风险API
        api_category_counts = {cat: 0 for cat in self.SUSPICIOUS_API_CATEGORIES}

        try:
            pe.parse_imports()
        except Exception:
            pass

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('ascii', errors='ignore').lower().rstrip('.dll')
                imported_dlls.add(dll_name)

                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('ascii', errors='ignore')
                        imported_functions.append(func_name)
                        # 检查是否是高风险API
                        base_name = func_name.rstrip('AW')  # 去掉Unicode/ANSI后缀
                        if base_name in self.SUSPICIOUS_APIS or func_name in self.SUSPICIOUS_APIS:
                            suspicious_count += 1
                        # 按类别统计
                        for cat, apis in self.SUSPICIOUS_API_CATEGORIES.items():
                            if base_name in apis or func_name in apis:
                                api_category_counts[cat] += 1
                                break

        features['imported_dll_count'] = len(imported_dlls)
        features['imported_function_count'] = len(imported_functions)
        features['suspicious_api_count'] = suspicious_count
        features['unique_dlls'] = '|'.join(sorted(imported_dlls)[:20])

        # API类别特征（用于家族区分）
        for cat, count in api_category_counts.items():
            features[f'api_cat_{cat}'] = count

        # 导入密度特征
        if len(imported_dlls) > 0:
            features['import_density'] = len(imported_functions) / len(imported_dlls)
        else:
            features['import_density'] = 0.0

        # DLL特征向量
        for dll in self.COMMON_DLLS:
            features[f'imports_{dll}'] = 1 if dll in imported_dlls else 0

        return features

    def _compute_file_entropy(self, file_path: str) -> float:
        """计算文件熵（大文件采样计算）"""
        try:
            file_size = os.path.getsize(file_path)
            # 大文件采样：超过1MB只取首尾+中间部分
            if file_size > 1024 * 1024:
                sample_size = 512 * 1024  # 采样512KB
                with open(file_path, 'rb') as f:
                    # 首部256KB
                    data = f.read(256 * 1024)
                    # 中部128KB
                    f.seek(file_size // 2)
                    data += f.read(128 * 1024)
                    # 尾部128KB
                    f.seek(max(0, file_size - 128 * 1024))
                    data += f.read(128 * 1024)
            else:
                with open(file_path, 'rb') as f:
                    data = f.read()
            if not data:
                return 0.0
            return self._compute_entropy_bytes(data)
        except Exception:
            return 0.0

    def _compute_entropy_bytes(self, data: bytes) -> float:
        """计算字节序列的熵"""
        if not data:
            return 0.0
        byte_counts = Counter(data)
        length = len(data)
        entropy = -sum(
            (count / length) * np.log2(count / length)
            for count in byte_counts.values()
        )
        return round(float(entropy), 4)

    def _compute_hash(self, file_path: str) -> str:
        """计算SHA256"""
        try:
            h = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ''

    def _fallback_features(self, file_path: str, base_features: Dict) -> Dict[str, Any]:
        """非PE文件的回退特征"""
        base_features['is_pe'] = False
        base_features['file_type'] = 'unknown'
        base_features['overall_entropy'] = self._compute_file_entropy(file_path)
        base_features['imported_dll_count'] = 0
        base_features['imported_function_count'] = 0
        base_features['suspicious_api_count'] = 0
        base_features['num_sections'] = 0
        base_features['has_packer_section'] = 0
        base_features['suspicious_section_count'] = 0
        base_features['executable_section_count'] = 0
        base_features['writable_section_count'] = 0
        base_features['section_entropy_mean'] = 0.0
        base_features['section_entropy_max'] = 0.0
        base_features['section_entropy_min'] = 0.0
        base_features['section_entropy_std'] = 0.0
        base_features['high_entropy_sections'] = 0
        base_features['compression_ratio'] = 0
        base_features['resource_count'] = 0
        base_features['has_debug'] = 0
        base_features['has_tls'] = 0
        base_features['machine'] = 0
        base_features['is_dll'] = 0
        base_features['is_exe'] = 0
        base_features['timestamp'] = 0
        base_features['total_raw_size'] = 0
        base_features['total_virtual_size'] = 0
        base_features['section_names'] = ''
        base_features['unique_dlls'] = ''
        base_features['import_density'] = 0.0
        # API类别默认值
        for cat in self.SUSPICIOUS_API_CATEGORIES:
            base_features[f'api_cat_{cat}'] = 0
        for dll in self.COMMON_DLLS:
            base_features[f'imports_{dll}'] = 0
        # .NET 特征默认值
        base_features.update(self._dotnet_extractor._default_features())
        return base_features


# ============================================================
# 行为特征提取（Pro模式，需要Speakeasy模拟报告）
# ============================================================

class BehaviorExtractor:
    """从Speakeasy模拟报告中提取行为特征"""

    # 固定的API类别映射 - 用于家族区分（行为特征核心）
    # 每个家族有典型的API调用模式：
    # - Ransomware: 文件加密、密钥生成
    # - Trojan: 网络通信、下载
    # - Backdoor: 进程注入、远程控制
    # - Spyware: 信息窃取、键盘记录
    BEHAVIOR_API_CATEGORIES = {
        'crypto': {  # 加密相关 - Ransomware特征
            'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'CryptDeriveKey',
            'CryptImportKey', 'CryptExportKey', 'CryptCreateHash', 'CryptHashData',
            'BCryptEncrypt', 'BCryptDecrypt', 'BCryptGenerateSymmetricKey',
        },
        'network': {  # 网络通信 - Trojan/Backdoor特征
            'InternetOpen', 'InternetOpenUrl', 'InternetConnect',
            'HttpOpenRequest', 'HttpSendRequest', 'InternetReadFile',
            'URLDownloadToFile', 'WSAStartup', 'connect', 'send', 'recv',
            'bind', 'listen', 'accept', 'socket',
        },
        'injection': {  # 进程注入 - Backdoor特征
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
            'NtUnmapViewOfSection', 'QueueUserAPC', 'NtQueueApcThread',
            'RtlCreateUserThread', 'SetWindowsHookEx',
        },
        'process': {  # 进程操作
            'CreateProcess', 'CreateProcessAsUser', 'OpenProcess',
            'TerminateProcess', 'WinExec', 'ShellExecute', 'ShellExecuteEx',
        },
        'registry': {  # 注册表 - 持久化
            'RegOpenKey', 'RegOpenKeyEx', 'RegSetValue', 'RegSetValueEx',
            'RegCreateKey', 'RegCreateKeyEx', 'RegDeleteKey', 'RegDeleteValue',
        },
        'file': {  # 文件操作 - Ransomware/Spyware
            'CreateFile', 'WriteFile', 'DeleteFile', 'MoveFile', 'CopyFile',
            'FindFirstFile', 'FindNextFile',
        },
        'antidebug': {  # 反调试
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'NtQueryInformationProcess', 'OutputDebugString',
        },
        'loader': {  # 动态加载
            'LoadLibrary', 'LoadLibraryEx', 'GetProcAddress', 'LdrLoadDll',
        },
        'privilege': {  # 提权
            'AdjustTokenPrivileges', 'LookupPrivilegeValue',
            'OpenProcessToken', 'ImpersonateLoggedOnUser',
        },
        'service': {  # 服务操作 - 持久化
            'CreateService', 'StartService', 'OpenSCManager',
            'ControlService', 'DeleteService',
        },
        'mem_alloc': {  # 内存操作
            'VirtualAlloc', 'VirtualProtect', 'VirtualFree',
            'HeapAlloc', 'HeapFree', 'malloc', 'free',
        },
        'sysinfo': {  # 系统信息收集 - Spyware
            'GetComputerName', 'GetUserName', 'GetVolumeInformation',
            'GetSystemDirectory', 'GetWindowsDirectory', 'GetTempPath',
            'GetLocaleInfo', 'GetTimeZoneInformation',
        },
    }

    # 典型恶意行为序列模式（bigram）
    SUSPICIOUS_BIGRAMS = {
        'VirtualAlloc->WriteProcessMemory',  # 注入
        'WriteProcessMemory->CreateRemoteThread',  # 注入
        'VirtualAllocEx->WriteProcessMemory',  # 注入
        'RegOpenKey->RegSetValue',  # 持久化
        'RegCreateKey->RegSetValue',  # 持久化
        'CreateFile->WriteFile',  # 文件操作
        'InternetOpen->InternetConnect',  # 网络通信
        'HttpOpenRequest->HttpSendRequest',  # HTTP请求
        'WSAStartup->connect',  # 网络连接
        'CryptGenKey->CryptEncrypt',  # 加密
        'LoadLibrary->GetProcAddress',  # 动态解析
    }

    def extract(self, report: Any) -> Dict[str, Any]:
        """从Speakeasy报告中提取行为特征"""
        features = {}

        # 兼容pydantic模型和dict
        if hasattr(report, 'model_dump'):
            r = report.model_dump()
        elif isinstance(report, dict):
            r = report
        else:
            r = vars(report)

        # 模拟元信息
        features['emulation_runtime'] = r.get('emulation_total_runtime', 0)
        features['arch'] = r.get('arch', 'unknown')

        entry_points = r.get('entry_points', []) or []
        features['entry_point_count'] = len(entry_points)

        # API调用统计
        api_counter = Counter()
        dll_counter = Counter()
        api_sequence = []  # 用于序列特征
        behavior_events = Counter()

        for ep in entry_points:
            events = ep.get('events', []) or []
            for event in events:
                event_type = event.get('event', 'unknown')
                behavior_events[event_type] += 1

                if event_type == 'api':
                    api_name = event.get('api_name', '')
                    if api_name:
                        api_counter[api_name] += 1
                        # 提取DLL名
                        dll_name = api_name.split('.')[0] if '.' in api_name else api_name
                        dll_counter[dll_name] += 1
                        api_sequence.append(api_name)

        # API统计特征
        features['total_api_calls'] = sum(api_counter.values())
        features['unique_api_count'] = len(api_counter)
        features['unique_dll_count'] = len(dll_counter)

        # 固定维度API类别特征（家族区分核心）
        # 统计每个类别的API调用次数
        for cat, apis in self.BEHAVIOR_API_CATEGORIES.items():
            count = sum(c for api, c in api_counter.items()
                       if any(a in api for a in apis))
            features[f'behavior_cat_{cat}'] = count

        # API类别多样性（每类是否有调用，用于家族指纹）
        for cat, apis in self.BEHAVIOR_API_CATEGORIES.items():
            has_calls = any(any(a in api for a in apis) for api in api_counter)
            features[f'behavior_has_{cat}'] = 1 if has_calls else 0

        # 行为事件统计
        features['network_events'] = (
            behavior_events.get('net_dns', 0) +
            behavior_events.get('net_http', 0) +
            behavior_events.get('net_traffic', 0)
        )
        features['file_events'] = (
            behavior_events.get('file_create', 0) +
            behavior_events.get('file_write', 0) +
            behavior_events.get('file_open', 0) +
            behavior_events.get('file_read', 0) +
            behavior_events.get('file_delete', 0)
        )
        features['registry_events'] = (
            behavior_events.get('reg_open_key', 0) +
            behavior_events.get('reg_read_value', 0) +
            behavior_events.get('reg_write_value', 0) +
            behavior_events.get('reg_create_key', 0) +
            behavior_events.get('reg_delete_key', 0)
        )
        features['process_events'] = (
            behavior_events.get('process_create', 0) +
            behavior_events.get('thread_create', 0) +
            behavior_events.get('thread_inject', 0)
        )
        features['memory_events'] = (
            behavior_events.get('mem_alloc', 0) +
            behavior_events.get('mem_write', 0) +
            behavior_events.get('mem_protect', 0)
        )
        features['exception_events'] = behavior_events.get('exception', 0)

        # 字符串特征
        strings = r.get('strings', None) or {}
        if isinstance(strings, dict):
            static_s = strings.get('static', {}) or {}
            in_memory = strings.get('in_memory', {}) or {}
            features['static_ansi_count'] = len(static_s.get('ansi', []))
            features['static_unicode_count'] = len(static_s.get('unicode', []))
            features['memory_ansi_count'] = len(in_memory.get('ansi', []))
            features['memory_unicode_count'] = len(in_memory.get('unicode', []))
            static_total = len(static_s.get('ansi', [])) + len(static_s.get('unicode', []))
            memory_total = len(in_memory.get('ansi', [])) + len(in_memory.get('unicode', []))
            features['decoded_strings'] = max(0, memory_total - static_total)
        else:
            features['static_ansi_count'] = 0
            features['static_unicode_count'] = 0
            features['memory_ansi_count'] = 0
            features['memory_unicode_count'] = 0
            features['decoded_strings'] = 0

        # 错误信息
        error_count = sum(1 for ep in entry_points if ep.get('error'))
        features['error_count'] = error_count

        # 动态代码段（解包指标）
        dynamic_code_count = sum(
            len(ep.get('dynamic_code_segments', []) or [])
            for ep in entry_points
        )
        features['dynamic_code_segments'] = dynamic_code_count

        # 释放文件
        dropped_files_count = sum(
            len(ep.get('dropped_files', []) or [])
            for ep in entry_points
        )
        features['dropped_files'] = dropped_files_count

        # API序列特征
        features['api_sequence_length'] = len(api_sequence)
        if len(api_sequence) > 0:
            # bigram统计
            bigrams = Counter()
            for i in range(len(api_sequence) - 1):
                # 提取API基础名（去掉dll前缀）
                api1 = api_sequence[i].split('.')[-1] if '.' in api_sequence[i] else api_sequence[i]
                api2 = api_sequence[i+1].split('.')[-1] if '.' in api_sequence[i+1] else api_sequence[i+1]
                bigram = f"{api1}->{api2}"
                bigrams[bigram] += 1
            features['unique_bigrams'] = len(bigrams)

            # 可疑bigram匹配数（固定维度，用于家族区分）
            suspicious_bigram_count = 0
            for suspicious in self.SUSPICIOUS_BIGRAMS:
                # 检查是否包含可疑模式
                for bigram in bigrams:
                    if all(part in bigram for part in suspicious.split('->')):
                        suspicious_bigram_count += 1
                        break
            features['suspicious_bigram_count'] = suspicious_bigram_count
        else:
            features['unique_bigrams'] = 0
            features['suspicious_bigram_count'] = 0

        return features


# ============================================================
# 特征向量化
# ============================================================

class FeatureVectorizer:
    """将提取的特征转换为数值向量"""

    # 数值特征列表（Flash模式 - 静态特征）
    # 注意：移除了 is_dll, is_exe, machine, timestamp 等高偏差特征
    STATIC_NUMERIC_FEATURES = [
        'file_size', 'file_size_log', 'overall_entropy',
        'num_sections', 'total_raw_size', 'total_virtual_size',
        'compression_ratio', 'has_packer_section',
        'suspicious_section_count', 'executable_section_count', 'writable_section_count',
        'section_entropy_mean', 'section_entropy_max', 'section_entropy_min',
        'section_entropy_std', 'high_entropy_sections',
        'resource_count', 'has_debug', 'has_tls',
        'imported_dll_count', 'imported_function_count', 'suspicious_api_count',
        'import_density',
    ]

    # API类别特征（用于家族区分）
    API_CATEGORY_FEATURES = [
        f'api_cat_{cat}' for cat in StaticExtractor.SUSPICIOUS_API_CATEGORIES
    ]

    # 静态导入特征（one-hot）
    STATIC_IMPORT_FEATURES = [
        f'imports_{dll}' for dll in StaticExtractor.COMMON_DLLS
    ]

    # .NET 元数据特征（方案 B：dnfile 解析，对所有样本提取，非 .NET 为 0）
    DOTNET_FEATURES = DotNetExtractor().get_feature_names()

    # 行为特征（Pro模式）- 固定维度
    BEHAVIOR_NUMERIC_FEATURES = [
        'emulation_runtime', 'entry_point_count',
        'total_api_calls', 'unique_api_count', 'unique_dll_count',
        'network_events', 'file_events', 'registry_events',
        'process_events', 'memory_events', 'exception_events',
        'static_ansi_count', 'static_unicode_count',
        'memory_ansi_count', 'memory_unicode_count',
        'decoded_strings', 'error_count',
        'dynamic_code_segments', 'dropped_files',
        'api_sequence_length', 'unique_bigrams', 'suspicious_bigram_count',
    ]

    # 行为API类别特征（固定维度，家族区分核心）
    BEHAVIOR_CATEGORY_FEATURES = [
        f'behavior_cat_{cat}' for cat in BehaviorExtractor.BEHAVIOR_API_CATEGORIES
    ] + [
        f'behavior_has_{cat}' for cat in BehaviorExtractor.BEHAVIOR_API_CATEGORIES
    ]

    def __init__(self, mode: str = 'flash'):
        """
        mode: 'flash' 仅静态特征, 'pro' 静态+行为特征
        """
        self.mode = mode
        self.feature_names = self._build_feature_names()
        self._dll_set = StaticExtractor.COMMON_DLLS

    def _build_feature_names(self) -> List[str]:
        names = list(self.STATIC_NUMERIC_FEATURES)
        names.extend(self.API_CATEGORY_FEATURES)
        names.extend(self.STATIC_IMPORT_FEATURES)
        # .NET 元数据特征（方案 B，flash 和 pro 模式都包含）
        names.extend(self.DOTNET_FEATURES)
        if self.mode == 'pro':
            names.extend(self.BEHAVIOR_NUMERIC_FEATURES)
            names.extend(self.BEHAVIOR_CATEGORY_FEATURES)
        return names

    def vectorize(self, features: Dict[str, Any]) -> np.ndarray:
        """将特征字典转换为数值向量"""
        vector = []
        for name in self.feature_names:
            val = features.get(name, 0)
            if isinstance(val, bool):
                val = int(val)
            elif isinstance(val, (int, float)):
                pass
            elif isinstance(val, str):
                # 字符串特征转为hash
                val = hash(val) % (2**31)
            else:
                val = 0
            vector.append(float(val))
        return np.array(vector, dtype=np.float64)

    def vectorize_batch(self, feature_list: List[Dict[str, Any]]) -> np.ndarray:
        """批量向量化"""
        return np.array([self.vectorize(f) for f in feature_list])
