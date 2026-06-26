"""
.NET 元数据特征提取器（方案 B 核心）

用 dnfile 解析 .NET 程序集元数据，提取 P/Invoke 引用的原生 API 作为
行为入口特征——这是 .NET 恶意软件的真正行为指示器（Speakeasy 无法模拟 .NET，
但 P/Invoke 直接暴露了原生 API 调用意图）。

特征维度（共 34 维，全部 dotnet_ 前缀）：
- 元数据统计：is_dotnet / typedef_count / methoddef_count / implmap_count / has_implmap
- 用户字符串：count / avg_len / has_url / has_base64 / has_file_path
- 程序集：assembly_count / has_pubkey
- P/Invoke 13 类别计数：injection / process / loader / antidebug / network / registry /
  file / crypto / privilege / service / mem_alloc / sysinfo / gui_keylogger
- 9 个高风险 API 二值特征：VirtualAlloc / CreateRemoteThread / WriteProcessMemory /
  LoadLibrary / GetProcAddress / URLDownloadToFile / InternetOpenUrl / ...
"""

import os
import re
import contextlib
from typing import Dict, Any, List, Optional

try:
    import dnfile
    _DNFILE_AVAILABLE = True
except ImportError:
    dnfile = None
    _DNFILE_AVAILABLE = False


# 屏蔽 dnfile 解析时的 stderr 噪音（"string missing trailing flag" 等）
@contextlib.contextmanager
def _silence_stderr():
    devnull = open(os.devnull, "w")
    old_err = os.dup(2)
    os.dup2(devnull.fileno(), 2)
    try:
        yield
    finally:
        os.dup2(old_err, 2)
        devnull.close()


class DotNetExtractor:
    """从 .NET PE 文件提取元数据特征（dnfile 0.18.0 API）"""

    # P/Invoke API 13 类别（与 BehaviorExtractor 12 类对齐 + 新增 gui_keylogger）
    # 每个类别是一组小写子串，匹配 API 名（大小写不敏感）即计入该类别
    PINVOKE_CATEGORIES = {
        # 注入 / 进程操作 - Backdoor/RAT 特征
        'injection': (
            'virtualalloc', 'virtualallocex', 'virtualprotect', 'virtualprotectex',
            'virtualfree', 'createremotethread', 'writeprocessmemory', 'readprocessmemory',
            'ntcreatethreadex', 'queueuserapc', 'setthreadcontext', 'getthreadcontext',
            'ntmapviewofsection', 'zwunmapviewofsection',
        ),
        # 进程操作
        'process': (
            'openprocess', 'createprocess', 'createprocessasuser', 'winexec',
            'shellexecute', 'terminateprocess', 'suspendthread', 'resumethread',
            'ntsetinformationthread', 'ntsetinformationprocess',
        ),
        # DLL/模块加载
        'loader': (
            'loadlibrary', 'loadlibraryex', 'getprocaddress', 'getmodulehandle',
            'getmodulefilename', 'freelibrary', 'ntloaddriver',
        ),
        # 反调试/反虚拟机
        'antidebug': (
            'isdebuggerpresent', 'checkremotedebuggerpresent', 'outputdebugstring',
            'ntquerysysteminformation', 'ntqueryinformationprocess',
            'gettickcount', 'queryperformancecounter', 'enumprocessmodules',
            'createtoolhelp32snapshot',
        ),
        # 网络通信 - Trojan/Backdoor 特征
        'network': (
            'internetopen', 'internetopenurl', 'internetconnect', 'httpopenrequest',
            'httpsendrequest', 'internetreadfile', 'urldownloadtofile',
            'wsastartup', 'wsacleanup', 'socket', 'connect', 'send', 'recv',
            'gethostbyname', 'getaddrinfo', 'winhttpopen', 'winhttpconnect',
            'winhttpsendrequest', 'winhttpreaddata', 'dnsquery',
        ),
        # 注册表 - 持久化
        'registry': (
            'regopenkey', 'regsetvalue', 'regcreatekey', 'regdeletekey',
            'regqueryvalue', 'regclosekey', 'regenumkey', 'regenumvalue',
        ),
        # 文件操作 - Ransomware/Spyware
        'file': (
            'createfile', 'writefile', 'readfile', 'deletefile', 'movefile',
            'copyfile', 'findfirstfile', 'findnextfile', 'setfileattributes',
            'createdirectory', 'shfileoperation', 'ntcreatefile', 'ntwritefile',
        ),
        # 加密 - Ransomware 特征
        'crypto': (
            'cryptacquirecontext', 'cryptencrypt', 'cryptdecrypt', 'cryptderivekey',
            'cryptcreatehash', 'crypthashdata', 'cryptgenkey', 'cryptimportkey',
            'cryptexportkey', 'bcryptopenalgorithm', 'bcrypthash', 'bcryptencrypt',
        ),
        # 提权
        'privilege': (
            'openprocesstoken', 'gettokeninformation', 'adjusttokenprivileges',
            'lookupprivilegevalue', 'impersonateloggedonuser', 'duplicatetokenex',
            'setthreadtoken',
        ),
        # 服务/SCM - 持久化
        'service': (
            'openscmanager', 'createservice', 'startservice', 'deleteservice',
            'controlservice', 'enumdependentservices',
        ),
        # 内存/堆
        'mem_alloc': (
            'heapalloc', 'heapfree', 'heapcreate', 'getprocessheap',
            'globalalloc', 'globalfree', 'localalloc', 'localfree',
            'ntallocatevirtualmemory', 'ntfreevirtualmemory',
        ),
        # 系统信息收集 - Spyware
        'sysinfo': (
            'getenvironmentvariable', 'getcomputername', 'getusername',
            'getsystemdirectory', 'getwindowsdirectory', 'gettemppath',
            'getvolumeinformation', 'getversionex',
        ),
        # GUI/键盘记录 - 新增（调研发现 .NET 恶意软件高频）
        'gui_keylogger': (
            'findwindow', 'findwindowex', 'getforegroundwindow', 'setwindowshookex',
            'getwindowtext', 'getwindowthreadprocessid', 'showwindow',
            'getasynckeystate', 'getkeyboardstate', 'tounicode', 'mapvirtualkey',
            'getkeyboardlayout', 'windowfrompoint', 'sendmessage',
        ),
    }

    # 高风险 API 二值特征（出现即 1）—— 这些是恶意软件的强信号
    HIGH_RISK_APIS = (
        'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect',
        'CreateRemoteThread', 'WriteProcessMemory', 'ReadProcessMemory',
        'LoadLibrary', 'GetProcAddress',
        'URLDownloadToFile', 'InternetOpenUrl',
        'NtSetInformationProcess', 'NtQueryInformationProcess',
    )

    # URL / base64 / 文件路径 检测正则
    _URL_RE = re.compile(r'https?://|ftp://|www\.', re.IGNORECASE)
    _BASE64_RE = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
    _FILE_PATH_RE = re.compile(r'[A-Za-z]:\\|\\\\[a-z0-9.$-]+\\', re.IGNORECASE)

    def __init__(self):
        self.available = _DNFILE_AVAILABLE

    def extract(self, file_path: str) -> Dict[str, Any]:
        """
        提取 .NET 元数据特征

        Returns:
            特征字典，键名全部以 dotnet_ 开头。非 .NET 文件返回全 0 默认值。
        """
        if not self.available:
            return self._default_features()

        with _silence_stderr():
            try:
                pe = dnfile.dnPE(file_path)
            except Exception:
                return self._default_features()

            try:
                if pe.net is None:
                    return self._default_features()

                features = self._default_features()
                features['dotnet_is_dotnet'] = 1

                mt = pe.net.mdtables
                if mt is None:
                    return features

                # 元数据统计
                self._extract_metadata_counts(mt, features)
                # P/Invoke API 分类
                pinvoke_apis = self._extract_pinvoke(mt, features)
                # 高风险 API 二值特征
                self._extract_high_risk_apis(pinvoke_apis, features)
                # 用户字符串
                self._extract_user_strings(pe, features)
                # 程序集信息
                self._extract_assembly(mt, features)

                return features
            finally:
                try:
                    pe.close()
                except Exception:
                    pass

    # ----------------------------------
    # 子提取器
    # ----------------------------------

    def _extract_metadata_counts(self, mt, features: Dict[str, Any]):
        """TypeDef / MethodDef / ImplMap 行数"""
        try:
            if mt.TypeDef is not None:
                features['dotnet_typedef_count'] = int(getattr(mt.TypeDef, 'num_rows', 0) or 0)
        except Exception:
            pass
        try:
            if mt.MethodDef is not None:
                features['dotnet_methoddef_count'] = int(getattr(mt.MethodDef, 'num_rows', 0) or 0)
        except Exception:
            pass
        try:
            if mt.ImplMap is not None and getattr(mt.ImplMap, 'num_rows', 0) > 0:
                features['dotnet_has_implmap'] = 1
                features['dotnet_implmap_count'] = int(mt.ImplMap.num_rows)
        except Exception:
            pass

    def _extract_pinvoke(self, mt, features: Dict[str, Any]) -> List[str]:
        """提取 P/Invoke API 名称并按类别计数，返回所有 API 名列表"""
        all_apis: List[str] = []
        try:
            if mt.ImplMap is None or getattr(mt.ImplMap, 'num_rows', 0) == 0:
                return all_apis

            # 准备 ModuleRef 查表（P/Invoke 引用的 DLL 名）
            mod_refs = []
            try:
                if mt.ModuleRef is not None:
                    mod_refs = list(mt.ModuleRef.rows)
            except Exception:
                pass

            for row in mt.ImplMap.rows:
                api_name = self._safe_heap_value(row.ImportName)
                if not api_name:
                    continue
                all_apis.append(api_name)

                # 按类别计数（大小写不敏感子串匹配）
                api_lower = api_name.lower()
                for cat, keywords in self.PINVOKE_CATEGORIES.items():
                    if any(kw in api_lower for kw in keywords):
                        features[f'dotnet_cat_{cat}'] += 1
        except Exception:
            pass
        return all_apis

    def _extract_high_risk_apis(self, pinvoke_apis: List[str], features: Dict[str, Any]):
        """高风险 API 二值特征"""
        if not pinvoke_apis:
            return
        api_set = {api.lower() for api in pinvoke_apis}
        for hr_api in self.HIGH_RISK_APIS:
            key = f'dotnet_hr_{hr_api.lower()}'
            # 精确匹配或包含匹配（去掉 A/W 后缀）
            base = hr_api.lower().rstrip('aw')
            if hr_api.lower() in api_set or any(base in a for a in api_set):
                features[key] = 1

    def _extract_user_strings(self, pe, features: Dict[str, Any]):
        """用户字符串统计特征"""
        try:
            us = pe.net.user_strings
            if us is None:
                return
            size = us.sizeof()
        except Exception:
            return

        strings: List[str] = []
        off = 1
        guard = 0
        while off < size and len(strings) < 100 and guard < 5000:
            guard += 1
            try:
                s = us.get(off)
            except Exception:
                off += 1
                continue
            try:
                v = s.value
            except Exception:
                v = None
            try:
                isz = s.item_size
            except Exception:
                isz = 0
            if isz <= 0:
                isz = 1
            if v:
                if isinstance(v, bytes):
                    try:
                        v = v.decode('utf-8', errors='ignore')
                    except Exception:
                        v = v.decode('latin-1', errors='ignore')
                v = str(v)
                if v.strip():
                    strings.append(v)
            off += isz

        if not strings:
            return

        features['dotnet_user_string_count'] = len(strings)
        total_len = sum(len(s) for s in strings)
        features['dotnet_user_string_avg_len'] = round(total_len / len(strings), 2)

        # 模式检测
        all_text = ' '.join(strings)
        if self._URL_RE.search(all_text):
            features['dotnet_has_url'] = 1
        if any(self._BASE64_RE.match(s) for s in strings if len(s) >= 20):
            features['dotnet_has_base64'] = 1
        if self._FILE_PATH_RE.search(all_text):
            features['dotnet_has_file_path'] = 1

    def _extract_assembly(self, mt, features: Dict[str, Any]):
        """程序集信息"""
        try:
            if mt.Assembly is None or getattr(mt.Assembly, 'num_rows', 0) == 0:
                return
            features['dotnet_assembly_count'] = int(mt.Assembly.num_rows)
            a = list(mt.Assembly.rows)[0]
            # PublicKey 非空即视为有签名
            try:
                pk = a.PublicKey
                if pk is not None:
                    # PublicKey 是字节流或 HeapItemString
                    pk_val = pk.value if hasattr(pk, 'value') else pk
                    if pk_val:
                        features['dotnet_has_pubkey'] = 1
            except Exception:
                pass
        except Exception:
            pass

    # ----------------------------------
    # 辅助
    # ----------------------------------

    @staticmethod
    def _safe_heap_value(heap_item) -> str:
        """从 HeapItemString 取 .value，失败返回空串"""
        try:
            v = heap_item.value
            if v is None:
                return ''
            if isinstance(v, bytes):
                try:
                    return v.decode('utf-8', errors='ignore')
                except Exception:
                    return v.decode('latin-1', errors='ignore')
            return str(v)
        except Exception:
            return ''

    def _default_features(self) -> Dict[str, Any]:
        """非 .NET 文件或解析失败的默认特征（全 0）"""
        features = {
            'dotnet_is_dotnet': 0,
            'dotnet_typedef_count': 0,
            'dotnet_methoddef_count': 0,
            'dotnet_implmap_count': 0,
            'dotnet_has_implmap': 0,
            'dotnet_user_string_count': 0,
            'dotnet_user_string_avg_len': 0.0,
            'dotnet_has_url': 0,
            'dotnet_has_base64': 0,
            'dotnet_has_file_path': 0,
            'dotnet_assembly_count': 0,
            'dotnet_has_pubkey': 0,
        }
        # 13 个 P/Invoke 类别
        for cat in self.PINVOKE_CATEGORIES:
            features[f'dotnet_cat_{cat}'] = 0
        # 12 个高风险 API
        for api in self.HIGH_RISK_APIS:
            features[f'dotnet_hr_{api.lower()}'] = 0
        return features

    def get_feature_names(self) -> List[str]:
        """返回固定顺序的特征名列表（用于向量化）"""
        names = [
            'dotnet_is_dotnet',
            'dotnet_typedef_count', 'dotnet_methoddef_count',
            'dotnet_implmap_count', 'dotnet_has_implmap',
            'dotnet_user_string_count', 'dotnet_user_string_avg_len',
            'dotnet_has_url', 'dotnet_has_base64', 'dotnet_has_file_path',
            'dotnet_assembly_count', 'dotnet_has_pubkey',
        ]
        names.extend(f'dotnet_cat_{cat}' for cat in self.PINVOKE_CATEGORIES)
        names.extend(f'dotnet_hr_{api.lower()}' for api in self.HIGH_RISK_APIS)
        return names
