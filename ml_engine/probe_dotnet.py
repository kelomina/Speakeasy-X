"""dnfile .NET 样本结构调研脚本（只读，不修改任何文件）。

调研内容：
1. 从 malicious_samples / benign_samples 各随机采样 50 个 PE 文件（random.seed(42)）。
2. 用 dnfile.dnPE 检测 .NET 程序集 vs 原生 PE。
3. 提取 .NET 元数据：ImplMap(P/Invoke)、TypeDef、MethodDef、Assembly、ModuleRef、user_strings。
4. 从 ImplMap 提取 P/Invoke 原生 API 名称并按类别归类。
5. 打印结构化报告。

dnfile 0.18.0 API 关键点：
- pe = dnfile.dnPE(path)；若 .net 为 None 或抛异常 -> 非 .NET/损坏
- 表在 pe.net.mdtables（注意：不是 pe.net.metadata.tables）
- mt.ImplMap / mt.MethodImpl / mt.TypeDef / mt.MethodDef / mt.Assembly / mt.ModuleRef
- 每个表有 .num_rows 和 .rows；行属性 ImportName.value（API名）、ImportScope.row_index（1-based 索引到 ModuleRef）
- ModuleRef.rows[idx-1].Name.value = DLL 名
- pe.net.user_strings.get(offset).value / .item_size；us.sizeof() 用于扫描上界
"""

import os
import sys
import random
import contextlib
from pathlib import Path
from collections import Counter, defaultdict

import dnfile

# 屏蔽 dnfile 解析时输出到 stderr 的 "string missing trailing flag" 等噪音
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


def collect_samples(base_dir, label, count, seed=42):
    """递归收集 base_dir 下所有文件，随机采样 count 个，返回绝对路径列表。"""
    random.seed(seed)
    files = []
    for p in Path(base_dir).rglob("*"):
        if p.is_file():
            files.append(str(p))
    if not files:
        return [], label
    k = min(count, len(files))
    return random.sample(files, k), label


# ---- P/Invoke API 分类规则 ----
# 基于子串匹配（大小写不敏感），覆盖 .NET 恶意软件常见原生 API。
PINVOKE_CATEGORIES = [
    ("注入/进程操作", [
        "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
        "virtualfree", "createremotethread", "writeprocessmemory", "readprocessmemory",
        "openprocess", "createprocess", "ntcreateprocessex", "ntcreatethreadex",
        "queueuserapc", "ntapc", "setthreadcontext", "getthreadcontext",
        "suspendthread", "resumethread", "terminateprocess", "terminateprocess",
        "ntsetinformationthread", "rtlcreatexxx", "zwunmapviewofsection",
        "ntmapviewofsection", "createmutex",
    ]),
    ("模块/DLL 加载", [
        "loadlibrary", "loadlibraryex", "getprocaddress", "getmodulehandle",
        "getmodulefilename", "freelibrary", "ntloaddriver",
    ]),
    ("网络/HTTP", [
        "internetopen", "internetopenurl", "internetconnect", "httpopenrequest",
        "httpsendrequest", "internetreadfile", "internetclosehandle",
        "wsastartup", "wsacleanup", "socket", "connect", "send", "recv",
        "gethostbyname", "getaddrinfo", "urldownloadtofilea", "urldownloadtofilew",
        "winhttpopen", "winhttpconnect", "winhttpsendrequest", "winhttpreaddata",
        "wininetopen", "winetget", "ftp", "dnsquery",
    ]),
    ("文件系统", [
        "createfile", "writefile", "readfile", "deletefile", "movefile",
        "copyfile", "findfirstfile", "findnextfile", "findclose",
        "setfileattributes", "getfileattributes", "createfolder", "createdirectory",
        "remove directory", "shfileoperation", "ntcreatefile", "ntwritefile",
        "ntreadfile", "ntopenfile",
    ]),
    ("注册表", [
        "regopenkey", "regsetvalue", "regcreatekey", "regdeletekey",
        "regqueryvalue", "regclosekey", "regenumkey", "regenumvalue",
    ]),
    ("反调试/反虚拟机", [
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntsetinformationthread",
        "outputdebugstring", "gettickcount", "queryperformancecounter",
        "ntquerysysteminformation", "ntqueryinformationprocess",
        "getmodulehandle", "enumprocessmodules", "createtoolhelp32snapshot",
    ]),
    ("加密", [
        "cryptacquirecontext", "cryptencrypt", "cryptdecrypt", "cryptderivekey",
        "cryptcreatehash", "crypthashdata", "cryptgenkey", "cryptimportkey",
        "cryptexportkey", "bcryptopenalgorithm", "bcrypthash",
    ]),
    ("服务/SCM", [
        "openscmanager", "createservice", "startservice", "deleteservice",
        "controlservice", "enumdependentservices",
    ]),
    ("令牌/权限", [
        "openprocesstoken", "gettokeninformation", "adjusttokenprivileges",
        "lookupprivilegevalue", "impersonateloggedonuser", "duplicatetokenex",
        "setthreadtoken", "seautocomplete", "ntimpersonatethread",
    ]),
    ("窗口/Shell", [
        "findwindow", "findwindowex", "getforegroundwindow", "setwindowshookex",
        "getwindowtext", "getwindowthreadprocessid", "showwindow",
        "shellexecute", "createprocessasuser",
    ]),
    ("环境/系统信息", [
        "getenvironmentvariable", "setenvironmentvariable", "getcomputername",
        "getusername", "getsystemdirectory", "getwindowsdirectory", "gettemp path",
        "getvolumeinformation", "getversionex", "ntsystemdebugcontrol",
    ]),
    ("内存/堆", [
        "heapalloc", "heapfree", "heapcreate", "getprocessheap",
        "globalalloc", "globalfree", "localalloc", "localfree",
        "ntallocatevirtualmemory", "ntfreevirtualmemory",
    ]),
]


def categorize_api(api_name):
    """返回 API 所属类别列表（一个 API 可能命中多个类别，返回第一个匹配的类别）。"""
    if not api_name:
        return "未分类"
    name = api_name.lower()
    for cat, keys in PINVOKE_CATEGORIES:
        for k in keys:
            if k in name:
                return cat
    return "未分类"


def safe_get_heap_string(heap_item):
    """从 HeapItemString 取 .value，失败返回空串。"""
    try:
        v = heap_item.value
        if v is None:
            return ""
        if isinstance(v, bytes):
            try:
                return v.decode("utf-8", errors="ignore")
            except Exception:
                return v.decode("latin-1", errors="ignore")
        return str(v)
    except Exception:
        return ""


def extract_user_strings(us, max_n=20, max_len=80):
    """扫描 UserStringHeap，返回非空字符串列表（最多 max_n 个，每个截断到 max_len 字符）。"""
    out = []
    if us is None:
        return out
    try:
        size = us.sizeof()
    except Exception:
        return out
    off = 1
    guard = 0
    while off < size and len(out) < max_n and guard < 5000:
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
                    v = v.decode("utf-8", errors="ignore")
                except Exception:
                    v = v.decode("latin-1", errors="ignore")
            v = str(v)
            if v.strip():
                out.append(v[:max_len])
        off += isz
    return out


def analyze_dotnet_sample(file_path):
    """解析单个 .NET 样本，返回结构化字典。不抛异常。"""
    info = {
        "path": file_path,
        "is_dotnet": False,
        "parse_error": None,
        "has_metadata": False,
        "has_implmap": False,
        "implmap_count": 0,
        "has_methodimpl": False,
        "typedef_count": 0,
        "methoddef_count": 0,
        "assembly_count": 0,
        "assembly_name": "",
        "assembly_version": "",
        "pinvoke_apis": [],   # [(api_name, dll_name)]
        "user_strings": [],
    }
    with _silence_stderr():
        try:
            pe = dnfile.dnPE(file_path)
        except Exception as e:
            info["parse_error"] = f"{type(e).__name__}: {str(e)[:120]}"
            return info

        try:
            if pe.net is None:
                return info
            info["is_dotnet"] = True
            mt = pe.net.mdtables
            if mt is None:
                return info
            info["has_metadata"] = True

            # ImplMap
            try:
                if mt.ImplMap is not None and getattr(mt.ImplMap, "num_rows", 0) > 0:
                    info["has_implmap"] = True
                    info["implmap_count"] = mt.ImplMap.num_rows
                    # 准备 ModuleRef 查表
                    mod_refs = []
                    try:
                        if mt.ModuleRef is not None:
                            mod_refs = list(mt.ModuleRef.rows)
                    except Exception:
                        mod_refs = []
                    for r in mt.ImplMap.rows:
                        api = safe_get_heap_string(r.ImportName)
                        dll = ""
                        try:
                            idx = r.ImportScope.row_index
                            if mod_refs and 0 < idx <= len(mod_refs):
                                dll = safe_get_heap_string(mod_refs[idx - 1].Name)
                        except Exception:
                            dll = ""
                        info["pinvoke_apis"].append((api, dll))
            except Exception:
                pass

            # MethodImpl
            try:
                if mt.MethodImpl is not None and getattr(mt.MethodImpl, "num_rows", 0) > 0:
                    info["has_methodimpl"] = True
            except Exception:
                pass

            # TypeDef
            try:
                if mt.TypeDef is not None:
                    info["typedef_count"] = getattr(mt.TypeDef, "num_rows", 0) or 0
            except Exception:
                pass

            # MethodDef
            try:
                if mt.MethodDef is not None:
                    info["methoddef_count"] = getattr(mt.MethodDef, "num_rows", 0) or 0
            except Exception:
                pass

            # Assembly
            try:
                if mt.Assembly is not None and getattr(mt.Assembly, "num_rows", 0) > 0:
                    info["assembly_count"] = mt.Assembly.num_rows
                    a = list(mt.Assembly.rows)[0]
                    info["assembly_name"] = safe_get_heap_string(a.Name)
                    info["assembly_version"] = f"{a.MajorVersion}.{a.MinorVersion}.{a.BuildNumber}.{a.RevisionNumber}"
            except Exception:
                pass

            # user_strings
            try:
                info["user_strings"] = extract_user_strings(pe.net.user_strings, max_n=20, max_len=80)
            except Exception:
                pass
        finally:
            try:
                pe.close()
            except Exception:
                pass
    return info


def print_report(results_mal, results_ben):
    print("\n" + "=" * 80)
    print("dnfile .NET 样本结构调研报告")
    print("=" * 80)

    def block(title, results):
        print("\n" + "-" * 70)
        print(f"[{title}] 样本数 = {len(results)}")
        print("-" * 70)
        dotnet = [r for r in results if r["is_dotnet"]]
        native = [r for r in results if not r["is_dotnet"]]
        print(f"  .NET 程序集: {len(dotnet)} ({len(dotnet)/max(len(results),1)*100:.1f}%)")
        print(f"  原生/损坏 PE: {len(native)} ({len(native)/max(len(results),1)*100:.1f}%)")
        if native:
            err_types = Counter()
            for r in native:
                err = r["parse_error"] or "pe.net is None"
                err_types[err[:60]] += 1
            print("  原生/失败原因 (top 5):")
            for err, c in err_types.most_common(5):
                print(f"    {c:3d}  {err}")
        return dotnet

    dotnet_mal = block("malicious", results_mal)
    dotnet_ben = block("benign", results_ben)
    all_dotnet = dotnet_mal + dotnet_ben

    # P/Invoke 覆盖率
    print("\n" + "-" * 70)
    print("P/Invoke 覆盖率（.NET 样本中有 P/Invoke 的比例）")
    print("-" * 70)
    for label, subset in [("malicious", dotnet_mal), ("benign", dotnet_ben)]:
        with_pinvoke = [r for r in subset if r["has_implmap"]]
        print(f"  {label:10s}: {len(with_pinvoke)}/{len(subset)} "
              f"({len(with_pinvoke)/max(len(subset),1)*100:.1f}%) 有 P/Invoke")

    # 典型 P/Invoke API 列表（前 20 最常见）
    print("\n" + "-" * 70)
    print("P/Invoke API 频次（前 20 最常见，跨全部 .NET 样本）")
    print("-" * 70)
    api_counter = Counter()
    api_dll = defaultdict(Counter)
    for r in all_dotnet:
        for api, dll in r["pinvoke_apis"]:
            api_counter[api] += 1
            api_dll[api][dll] += 1
    if api_counter:
        for api, c in api_counter.most_common(20):
            top_dlls = ",".join(f"{d}" for d, _ in api_dll[api].most_common(2))
            print(f"  {c:4d}  {api:40s}  <- {top_dlls}")
    else:
        print("  (无 P/Invoke API)")

    # P/Invoke API 类别分布
    print("\n" + "-" * 70)
    print("P/Invoke API 类别分布（按 API 命中次数）")
    print("-" * 70)
    cat_counter = Counter()
    for r in all_dotnet:
        for api, _ in r["pinvoke_apis"]:
            cat_counter[categorize_api(api)] += 1
    for cat, c in cat_counter.most_common():
        print(f"  {c:5d}  {cat}")

    # 每个类别内的样例 API
    print("\n" + "-" * 70)
    print("各类别典型 API（前 5）")
    print("-" * 70)
    cat_apis = defaultdict(Counter)
    for r in all_dotnet:
        for api, _ in r["pinvoke_apis"]:
            cat_apis[categorize_api(api)][api] += 1
    for cat, cnt in cat_counter.most_common():
        apis = ", ".join(f"{a}" for a, _ in cat_apis[cat].most_common(5))
        print(f"  [{cat}] ({cnt}): {apis}")

    # 用户字符串示例（前 5 个 .NET 样本各 3 个字符串）
    print("\n" + "-" * 70)
    print("用户字符串示例（前 5 个 .NET 样本各 3 个字符串）")
    print("-" * 70)
    shown = 0
    for r in all_dotnet:
        if shown >= 5:
            break
        if not r["user_strings"]:
            continue
        print(f"\n  样本: {Path(r['path']).name}  (asm={r['assembly_name']} v{r['assembly_version']})")
        for s in r["user_strings"][:3]:
            # 转义控制字符避免破坏终端
            esc = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
            print(f"    | {esc}")
        shown += 1

    # 元数据规模分布
    print("\n" + "-" * 70)
    print(".NET 元数据规模（TypeDef / MethodDef 行数）")
    print("-" * 70)
    for label, subset in [("malicious", dotnet_mal), ("benign", dotnet_ben)]:
        if not subset:
            continue
        td = [r["typedef_count"] for r in subset]
        md = [r["methoddef_count"] for r in subset]
        im = [r["implmap_count"] for r in subset]
        td.sort(); md.sort(); im.sort()
        def stat(name, arr):
            if not arr:
                print(f"    {name}: (空)")
                return
            print(f"    {name:14s}: n={len(arr)} min={min(arr)} med={arr[len(arr)//2]} "
                  f"max={max(arr)} mean={sum(arr)/len(arr):.1f}")
        print(f"  [{label}]")
        stat("TypeDef", td)
        stat("MethodDef", md)
        stat("ImplMap(P/Invoke)", im)

    # 程序集名示例
    print("\n" + "-" * 70)
    print("程序集名（Assembly 表，前 10 个非空，去重）")
    print("-" * 70)
    seen = set()
    for r in all_dotnet:
        name = r["assembly_name"]
        if name and name not in seen:
            seen.add(name)
            print(f"  {name}  v{r['assembly_version']}")
            if len(seen) >= 10:
                break

    # 特征化方案建议
    print("\n" + "-" * 70)
    print("推荐的特征化方案")
    print("-" * 70)
    recs = [
        "1) is_dotnet 布尔特征（dnfile 能否解析且 pe.net 非空）—— 区分 .NET / 原生 PE 的首要信号。",
        "2) P/Invoke 计数特征：ImplMap 行数（implmap_count）、是否含 P/Invoke（has_implmap）。",
        "3) P/Invoke API 类别向量：按 13 个类别（注入/网络/文件/注册表/反调试/...）统计每个样本的 API 命中数，",
        "   构成稀疏 13 维向量—— 恶意软件在注入/进程类 API 上通常显著高于良性。",
        "4) 高风险 API 二值特征：VirtualAlloc / CreateRemoteThread / WriteProcessMemory /",
        "   LoadLibrary / GetProcAddress / URLDownloadToFile 等是否出现（1/0）。",
        "5) 元数据规模特征：TypeDef 数、MethodDef 数（极小或极大都可能异常）。",
        "6) 用户字符串特征：数量、平均长度、是否含 URL/file:///、是否含 base64 串、是否含 GUID。",
        "7) 程序集特征：Assembly 名、版本号、PublicKey 是否为空（恶意常无签名）。",
        "8) 与现有 pefile 特征互补：pefile 覆盖原生 PE 导入/导出/节区；dnfile 补齐 .NET 元数据，",
        "   两者并集覆盖全部样本。Speakeasy 模拟无法跑 .NET，dnfile 提取的 P/Invoke API 正是行为入口，",
        "   可作为 .NET 样本的等价行为特征喂给 ml_engine 的分类器。",
    ]
    for r in recs:
        print("  " + r)


def main():
    data_dir = Path(r"e:\Project\python\Speakeasy-X\data")
    mal_dir = data_dir / "malicious_samples"
    ben_dir = data_dir / "benign_samples"

    print("dnfile .NET 结构调研（只读）")
    print(f"data_dir = {data_dir}")
    print(f"malicious_samples 存在: {mal_dir.is_dir()}")
    print(f"benign_samples   存在: {ben_dir.is_dir()}")

    # 1. 采样
    mal_files, _ = collect_samples(mal_dir, "malicious", 50, seed=42)
    ben_files, _ = collect_samples(ben_dir, "benign", 50, seed=42)
    print(f"采样: malicious={len(mal_files)} benign={len(ben_files)} 共 {len(mal_files)+len(ben_files)}")

    # 2. 解析
    results_mal = []
    for i, fp in enumerate(mal_files, 1):
        if i % 10 == 0:
            print(f"  [malicious] {i}/{len(mal_files)}")
        results_mal.append(analyze_dotnet_sample(fp))

    results_ben = []
    for i, fp in enumerate(ben_files, 1):
        if i % 10 == 0:
            print(f"  [benign] {i}/{len(ben_files)}")
        results_ben.append(analyze_dotnet_sample(fp))

    # 3. 报告
    print_report(results_mal, results_ben)


if __name__ == "__main__":
    main()
