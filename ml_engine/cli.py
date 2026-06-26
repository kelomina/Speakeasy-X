"""
Speakeasy-X ML CLI
机器学习病毒识别引擎命令行接口

子命令:
  detect      单文件检测（Flash + Pro 两阶段）
  batch       批量检测目录
  train-flash 训练 Flash 模型（纯静态特征）
  train-pro   训练 Pro 模型（需要 Speakeasy 模拟）
  info        查看已加载模型信息
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

console = Console()
logger = logging.getLogger("ml_engine")


def setup_logging(verbose: bool = False):
    """配置日志"""
    root = logging.getLogger("ml_engine")
    root.handlers.clear()
    root.addHandler(RichHandler(console=Console(stderr=True), show_path=False))
    root.setLevel(logging.DEBUG if verbose else logging.INFO)


# ============================================================
# 默认模型路径
# ============================================================

DEFAULT_MODELS_DIR = Path(__file__).parent / "models"
DEFAULT_FLASH_MODEL = DEFAULT_MODELS_DIR / "flash_v2"
DEFAULT_PRO_MODEL = DEFAULT_MODELS_DIR / "pro_v1"


# ============================================================
# 子命令实现
# ============================================================

def cmd_detect(args: argparse.Namespace) -> int:
    """单文件检测"""
    from .detection_engine import TwoStageDetector

    target = Path(args.target).resolve()
    if not target.is_file():
        console.print(f"[red]文件不存在: {target}[/red]")
        return 1

    flash_dir = args.flash_model or str(DEFAULT_FLASH_MODEL)
    pro_dir = args.pro_model or (str(DEFAULT_PRO_MODEL) if DEFAULT_PRO_MODEL.exists() else None)

    if not Path(flash_dir).exists():
        console.print(f"[red]Flash 模型不存在: {flash_dir}[/red]")
        return 1

    detector = TwoStageDetector(
        flash_model_dir=flash_dir,
        pro_model_dir=pro_dir,
        confidence_threshold=args.threshold,
        enable_pro=not args.flash_only,
        simulation_timeout=args.timeout,
    )

    console.print(f"\n[bold]检测文件:[/bold] {target.name}")
    console.print(f"[bold]文件大小:[/bold] {target.stat().st_size:,} bytes\n")

    start = time.time()
    result = detector.detect(str(target), run_simulation=not args.flash_only)
    elapsed = time.time() - start

    _print_detection_result(result, verbose=args.verbose)
    console.print(f"\n[dim]总耗时: {elapsed:.2f}s[/dim]")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False, default=str)
        console.print(f"[dim]结果已保存: {args.output}[/dim]")

    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    """批量检测"""
    from .detection_engine import TwoStageDetector

    target_dir = Path(args.target_dir).resolve()
    if not target_dir.is_dir():
        console.print(f"[red]目录不存在: {target_dir}[/red]")
        return 1

    # 收集 PE 文件
    extensions = {'.exe', '.dll'} if not args.include_all else None
    files = []
    for f in target_dir.rglob('*'):
        if not f.is_file():
            continue
        if extensions is None or f.suffix.lower() in extensions:
            files.append(str(f))

    if not files:
        console.print(f"[red]未找到可检测的文件: {target_dir}[/red]")
        return 1

    console.print(f"[bold]发现 {len(files)} 个文件[/bold]\n")

    flash_dir = args.flash_model or str(DEFAULT_FLASH_MODEL)
    pro_dir = args.pro_model or (str(DEFAULT_PRO_MODEL) if DEFAULT_PRO_MODEL.exists() else None)

    detector = TwoStageDetector(
        flash_model_dir=flash_dir,
        pro_model_dir=pro_dir,
        confidence_threshold=args.threshold,
        enable_pro=not args.flash_only,
        simulation_timeout=args.timeout,
    )

    results = detector.detect_batch(files, run_simulation=not args.flash_only)

    # 汇总
    table = Table(title="检测结果汇总", show_lines=True)
    table.add_column("文件", style="cyan")
    table.add_column("预测", style="bold")
    table.add_column("置信度", justify="right")
    table.add_column("阶段", justify="center")
    table.add_column("家族", style="magenta")
    table.add_column("耗时(s)", justify="right")

    pred_colors = {'malicious': 'red', 'benign': 'green', 'uncertain': 'yellow'}

    for r in results:
        table.add_row(
            Path(r.file_path).name,
            f"[{pred_colors.get(r.prediction, 'white')}]{r.prediction}[/{pred_colors.get(r.prediction, 'white')}]",
            f"{r.confidence:.4f}",
            r.stage,
            r.family or '-',
            f"{r.processing_time:.2f}",
        )

    console.print(table)

    # 统计
    from collections import Counter
    pred_counter = Counter(r.prediction for r in results)
    stage_counter = Counter(r.stage for r in results)

    console.print(f"\n[bold]统计:[/bold]")
    console.print(f"  预测: {dict(pred_counter)}")
    console.print(f"  阶段: {dict(stage_counter)}")

    if args.output:
        out_data = {
            'total': len(results),
            'predictions': dict(pred_counter),
            'stages': dict(stage_counter),
            'results': [r.to_dict() for r in results],
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(out_data, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"\n[dim]结果已保存: {args.output}[/dim]")

    return 0


def cmd_train_flash(args: argparse.Namespace) -> int:
    """训练 Flash 模型"""
    from .ml_pipeline import MLPipeline

    data_dir = Path(args.data_dir).resolve()
    malicious_dir = data_dir / 'malicious_samples'
    benign_dir = data_dir / 'benign_samples'

    if not malicious_dir.is_dir() or not benign_dir.is_dir():
        console.print(f"[red]数据目录不存在: {malicious_dir} / {benign_dir}[/red]")
        return 1

    malicious_files = [str(f) for f in malicious_dir.rglob('*') if f.is_file()]
    benign_files = [str(f) for f in benign_dir.rglob('*') if f.is_file()]

    console.print(f"恶意样本: {len(malicious_files)}")
    console.print(f"良性样本: {len(benign_files)}")

    if args.sample_count > 0:
        import random
        random.seed(42)
        malicious_files = random.sample(malicious_files, min(args.sample_count, len(malicious_files)))
        benign_files = random.sample(benign_files, min(args.sample_count, len(benign_files)))
        console.print(f"采样后: 恶意={len(malicious_files)}, 良性={len(benign_files)}")

    pipeline = MLPipeline(
        mode='flash',
        n_clusters=args.n_clusters,
        cluster_method=args.cluster_method,
        n_pca=args.n_pca,
    )

    X, y = pipeline.prepare_training_data(malicious_files, benign_files)
    metrics = pipeline.train(X, y)

    malicious_X = X[y == 1]
    if len(malicious_X) >= args.n_clusters:
        pipeline.cluster_malware_families(malicious_X)

    output_dir = args.output or str(DEFAULT_MODELS_DIR / 'flash_v3')
    pipeline.save(output_dir)

    console.print(f"\n[bold green]训练完成[/bold green]")
    console.print(f"  F1: {metrics.get('f1', 0):.4f}")
    console.print(f"  Accuracy: {metrics.get('accuracy', 0):.4f}")
    console.print(f"  CV F1: {metrics.get('cv_f1_mean', 0):.4f} ± {metrics.get('cv_f1_std', 0):.4f}")
    console.print(f"  模型保存: {output_dir}")

    return 0


def cmd_train_pro(args: argparse.Namespace) -> int:
    """训练 Pro 模型（需 Speakeasy 模拟）"""
    from .detection_engine import train_pro_model

    data_dir = Path(args.data_dir).resolve()
    malicious_dir = data_dir / 'malicious_samples'
    benign_dir = data_dir / 'benign_samples'

    if not malicious_dir.is_dir() or not benign_dir.is_dir():
        console.print(f"[red]数据目录不存在: {malicious_dir} / {benign_dir}[/red]")
        return 1

    malicious_files = [str(f) for f in malicious_dir.rglob('*') if f.is_file()]
    benign_files = [str(f) for f in benign_dir.rglob('*') if f.is_file()]

    console.print(f"恶意样本池: {len(malicious_files)}")
    console.print(f"良性样本池: {len(benign_files)}")
    console.print(f"每类采样: {args.sample_count}")
    console.print(f"模拟超时: {args.timeout}s/样本")
    console.print(f"\n[yellow]注意: Pro 训练需要运行 Speakeasy 模拟，耗时较长[/yellow]\n")

    output_dir = args.output or str(DEFAULT_MODELS_DIR / 'pro_v1')

    metrics = train_pro_model(
        malicious_files=malicious_files,
        benign_files=benign_files,
        output_dir=output_dir,
        sample_count=args.sample_count,
        simulation_timeout=args.timeout,
        n_clusters=args.n_clusters,
        cluster_method=args.cluster_method,
        n_pca=args.n_pca,
    )

    console.print(f"\n[bold green]Pro 模型训练完成[/bold green]")
    console.print(f"  F1: {metrics.get('f1', 0):.4f}")
    console.print(f"  Accuracy: {metrics.get('accuracy', 0):.4f}")
    console.print(f"  模拟成功: {metrics.get('simulation_success', 0)}")
    console.print(f"  模拟失败: {metrics.get('simulation_fail', 0)}")
    console.print(f"  有效恶意样本: {metrics.get('valid_malicious', 0)}")
    console.print(f"  有效良性样本: {metrics.get('valid_benign', 0)}")
    console.print(f"  模型保存: {output_dir}")

    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """查看已加载模型信息"""
    from .ml_pipeline import MLPipeline
    import joblib

    models_dir = Path(args.models_dir or DEFAULT_MODELS_DIR)
    if not models_dir.is_dir():
        console.print(f"[red]模型目录不存在: {models_dir}[/red]")
        return 1

    table = Table(title="已安装模型", show_lines=True)
    table.add_column("模型", style="cyan")
    table.add_column("模式", style="bold")
    table.add_column("特征维度", justify="right")
    table.add_column("聚类方法", justify="center")
    table.add_column("家族数", justify="right")
    table.add_column("F1", justify="right")

    for model_dir in sorted(models_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        meta_file = model_dir / 'metadata.json'
        if not meta_file.exists():
            continue

        try:
            with open(meta_file, encoding='utf-8') as f:
                meta = json.load(f)

            mode = meta.get('mode', '?')
            n_features = len(meta.get('vectorizer_features', []))

            # 加载 clusterer 获取详细信息
            clusterer_file = model_dir / 'clusterer.pkl'
            n_clusters = '-'
            cluster_method = '-'
            if clusterer_file.exists():
                try:
                    clusterer_data = joblib.load(clusterer_file)
                    n_clusters = str(clusterer_data.get('n_clusters', '-'))
                    cluster_method = clusterer_data.get('method', '-')
                except Exception:
                    pass

            # 加载 classifier 获取 F1
            classifier_file = model_dir / 'classifier.pkl'
            f1_score = '-'
            if classifier_file.exists():
                try:
                    classifier_data = joblib.load(classifier_file)
                    meta_c = classifier_data.get('metadata', {})
                    f1 = meta_c.get('f1')
                    if f1 is not None:
                        f1_score = f"{f1:.4f}"
                except Exception:
                    pass

            table.add_row(
                model_dir.name,
                mode,
                str(n_features),
                cluster_method,
                n_clusters,
                f1_score,
            )
        except Exception as e:
            console.print(f"[red]读取模型失败 {model_dir}: {e}[/red]")

    console.print(table)
    return 0


# ============================================================
# 输出辅助
# ============================================================

def _print_detection_result(result, verbose: bool = False):
    """格式化打印检测结果"""
    from rich.panel import Panel

    pred_colors = {
        'malicious': 'bold red',
        'benign': 'bold green',
        'uncertain': 'bold yellow',
    }
    stage_colors = {'flash': 'cyan', 'pro': 'magenta'}

    lines = []
    lines.append(f"[{pred_colors.get(result.prediction, 'white')}]{result.prediction.upper()}[/{pred_colors.get(result.prediction, 'white')}]")
    lines.append(f"置信度: [bold]{result.confidence:.4f}[/bold]")
    lines.append(f"检测阶段: [{stage_colors.get(result.stage, 'white')}]{result.stage}[/{stage_colors.get(result.stage, 'white')}]")
    if result.family:
        lines.append(f"家族: [magenta]{result.family}[/magenta]")
    lines.append(f"SHA256: [dim]{result.sha256[:16]}...[/dim]")
    lines.append(f"耗时: {result.processing_time:.3f}s")
    if result.error:
        lines.append(f"错误: [yellow]{result.error}[/yellow]")

    console.print(Panel("\n".join(lines), title=f"检测结果 - {Path(result.file_path).name}"))

    if verbose and result.features:
        # 显示关键特征
        feat = result.features
        key_features = Table(title="关键特征", show_lines=False)
        key_features.add_column("特征", style="cyan")
        key_features.add_column("值", justify="right")

        important_keys = [
            'file_size', 'overall_entropy', 'num_sections',
            'imported_dll_count', 'suspicious_api_count',
            'section_entropy_max', 'has_packer_section',
            'total_api_calls', 'network_events', 'file_events',
            'registry_events', 'process_events',
        ]
        for k in important_keys:
            if k in feat:
                v = feat[k]
                if isinstance(v, (int, float)):
                    if isinstance(v, float):
                        v = f"{v:.4f}"
                    else:
                        v = f"{v:,}"
                key_features.add_row(k, str(v))

        console.print(key_features)


# ============================================================
# 参数解析
# ============================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="speakeasy-ml",
        description="Speakeasy-X 机器学习病毒识别引擎 CLI",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="启用详细日志")
    sub = parser.add_subparsers(dest="command", required=True)

    # detect
    p_detect = sub.add_parser("detect", help="检测单个文件")
    p_detect.add_argument("target", help="目标文件路径")
    p_detect.add_argument("-o", "--output", help="结果输出 JSON 文件路径")
    p_detect.add_argument("--flash-model", help="Flash 模型目录（默认使用内置）")
    p_detect.add_argument("--pro-model", help="Pro 模型目录")
    p_detect.add_argument("--flash-only", action="store_true", help="仅使用 Flash 模式（不模拟）")
    p_detect.add_argument("--threshold", type=float, default=0.85, help="Flash 置信度阈值")
    p_detect.add_argument("--timeout", type=int, default=20, help="Pro 模拟超时秒数")
    p_detect.set_defaults(func=cmd_detect)

    # batch
    p_batch = sub.add_parser("batch", help="批量检测目录")
    p_batch.add_argument("target_dir", help="目标目录")
    p_batch.add_argument("-o", "--output", help="结果输出 JSON 文件路径")
    p_batch.add_argument("--flash-model", help="Flash 模型目录")
    p_batch.add_argument("--pro-model", help="Pro 模型目录")
    p_batch.add_argument("--flash-only", action="store_true", help="仅使用 Flash 模式")
    p_batch.add_argument("--include-all", action="store_true", help="包含所有文件类型（默认只 .exe/.dll）")
    p_batch.add_argument("--threshold", type=float, default=0.85, help="Flash 置信度阈值")
    p_batch.add_argument("--timeout", type=int, default=20, help="Pro 模拟超时秒数")
    p_batch.set_defaults(func=cmd_batch)

    # train-flash
    p_tf = sub.add_parser("train-flash", help="训练 Flash 模型")
    p_tf.add_argument("data_dir", help="数据目录（含 malicious_samples/ 和 benign_samples/）")
    p_tf.add_argument("-o", "--output", help="模型输出目录")
    p_tf.add_argument("--sample-count", type=int, default=0, help="每类采样数（0=全部）")
    p_tf.add_argument("--n-clusters", type=int, default=8, help="聚类家族数")
    p_tf.add_argument("--cluster-method", default='gmm', choices=['gmm', 'kmeans', 'minibatch', 'dbscan'])
    p_tf.add_argument("--n-pca", type=int, default=15, help="PCA 降维维度")
    p_tf.set_defaults(func=cmd_train_flash)

    # train-pro
    p_tp = sub.add_parser("train-pro", help="训练 Pro 模型（需 Speakeasy 模拟）")
    p_tp.add_argument("data_dir", help="数据目录")
    p_tp.add_argument("-o", "--output", help="模型输出目录")
    p_tp.add_argument("--sample-count", type=int, default=100, help="每类采样数（模拟耗时，建议 ≤200）")
    p_tp.add_argument("--timeout", type=int, default=20, help="单样本模拟超时秒数")
    p_tp.add_argument("--n-clusters", type=int, default=8, help="聚类家族数")
    p_tp.add_argument("--cluster-method", default='gmm', choices=['gmm', 'kmeans', 'minibatch', 'dbscan'])
    p_tp.add_argument("--n-pca", type=int, default=15, help="PCA 降维维度")
    p_tp.set_defaults(func=cmd_train_pro)

    # info
    p_info = sub.add_parser("info", help="查看已安装模型信息")
    p_info.add_argument("--models-dir", help="模型根目录（默认 ml_engine/models）")
    p_info.set_defaults(func=cmd_info)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(verbose=getattr(args, 'verbose', False))

    # Windows multiprocessing 保护
    if sys.platform == 'win32':
        import multiprocessing as mp
        mp.freeze_support()

    try:
        return args.func(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]用户中断[/yellow]")
        return 130
    except Exception as e:
        logger.exception("命令执行失败")
        console.print(f"\n[red]错误: {e}[/red]")
        return 1


if __name__ == '__main__':
    sys.exit(main())
