"""
两阶段检测引擎：Flash + Pro
- Flash阶段：纯静态特征，<1秒，快速筛选
- Pro阶段：模拟执行+行为特征，10-20秒，深度分析

注意：Windows 不支持 signal.alarm，使用 multiprocessing.Process 实现强制超时
"""

import json
import time
import logging
import multiprocessing as mp
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict, field

import numpy as np
import joblib

from .feature_extractor import StaticExtractor, BehaviorExtractor, FeatureVectorizer
from .ml_pipeline import MalwareClassifier, MalwareFamilyClusterer, MLPipeline

logger = logging.getLogger(__name__)


# ============================================================
# 模拟报告获取（子进程强制超时，Windows 兼容）
# ============================================================

def _simulate_worker(file_path: str, queue: mp.Queue):
    """子进程模拟 worker，将结果通过 queue 返回"""
    try:
        # 延迟导入：避免父进程 fork 时初始化 Speakeasy
        from speakeasy import Speakeasy
        se = Speakeasy()
        module = se.load_module(file_path)
        se.run_module(module, all_entrypoints=True)
        report = se.get_json_report()
        # get_json_report 返回 JSON 字符串
        if isinstance(report, str):
            result = json.loads(report)
        else:
            result = report
        queue.put(('success', result))
    except Exception as e:
        queue.put(('error', str(e)))


def simulate_with_timeout(file_path: str, timeout: int = 20) -> Optional[Dict[str, Any]]:
    """
    带强制超时的 Speakeasy 模拟

    Args:
        file_path: PE 文件路径
        timeout: 超时秒数

    Returns:
        模拟报告字典；失败返回 None
    """
    queue: mp.Queue = mp.Queue()
    proc = mp.Process(target=_simulate_worker, args=(file_path, queue))
    proc.daemon = True
    proc.start()
    proc.join(timeout=timeout)

    if proc.is_alive():
        # 超时：强制终止
        proc.terminate()
        proc.join(timeout=5)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=2)
        logger.debug("Speakeasy 模拟超时: %s", file_path)
        return None

    try:
        status, result = queue.get_nowait()
        if status == 'success':
            return result
        logger.debug("Speakeasy 模拟失败: %s - %s", file_path, result)
        return None
    except Exception:
        return None


# ============================================================
# 检测结果
# ============================================================

@dataclass
class DetectionResult:
    """检测结果"""
    file_path: str
    sha256: str
    prediction: str  # 'malicious' / 'benign' / 'uncertain'
    confidence: float
    stage: str  # 'flash' / 'pro'
    family: Optional[str] = None
    features: Optional[Dict[str, Any]] = None
    simulation_report: Optional[Dict[str, Any]] = None
    processing_time: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（移除 None 值）"""
        result = asdict(self)
        return {k: v for k, v in result.items() if v is not None}


# ============================================================
# 两阶段检测器
# ============================================================

class TwoStageDetector:
    """两阶段检测引擎：Flash 静态快速筛选 + Pro 行为深度分析"""

    def __init__(
        self,
        flash_model_dir: str,
        pro_model_dir: Optional[str] = None,
        confidence_threshold: float = 0.85,
        enable_pro: bool = True,
        simulation_timeout: int = 20,
    ):
        """
        初始化两阶段检测器

        Args:
            flash_model_dir: Flash 模型目录
            pro_model_dir: Pro 模型目录（可选，None 则禁用 Pro）
            confidence_threshold: 置信度阈值，低于此值进入 Pro 阶段
            enable_pro: 是否允许进入 Pro 阶段
            simulation_timeout: Speakeasy 模拟超时秒数
        """
        self.confidence_threshold = confidence_threshold
        self.enable_pro = enable_pro and pro_model_dir is not None
        self.simulation_timeout = simulation_timeout

        # 加载 Flash 模型
        logger.info("加载 Flash 模型: %s", flash_model_dir)
        self.flash_pipeline = MLPipeline.load(flash_model_dir, mode='flash')

        # 加载 Pro 模型（可选）
        if self.enable_pro:
            logger.info("加载 Pro 模型: %s", pro_model_dir)
            self.pro_pipeline = MLPipeline.load(pro_model_dir, mode='pro')
        else:
            self.pro_pipeline = None

        # 特征提取器
        self.static_extractor = StaticExtractor()
        self.behavior_extractor = BehaviorExtractor()

        logger.info(
            "两阶段检测器初始化完成 (Flash=%s, Pro=%s, 阈值=%.2f, 模拟超时=%ds)",
            flash_model_dir,
            '启用' if self.enable_pro else '禁用',
            confidence_threshold,
            simulation_timeout,
        )

    # ----------------------------------
    # 主检测入口
    # ----------------------------------

    def detect(self, file_path: str, run_simulation: bool = True) -> DetectionResult:
        """
        检测单个文件

        Args:
            file_path: 文件路径
            run_simulation: 是否允许运行 Pro 模拟（False 时只跑 Flash）

        Returns:
            DetectionResult
        """
        start_time = time.time()
        file_path = str(file_path)
        sha256 = self.static_extractor._compute_hash(file_path)

        # ---------- 第一阶段：Flash ----------
        try:
            flash_result = self._flash_detect(file_path)
        except Exception as e:
            logger.exception("Flash 阶段异常")
            return DetectionResult(
                file_path=file_path,
                sha256=sha256,
                prediction='uncertain',
                confidence=0.0,
                stage='flash',
                processing_time=time.time() - start_time,
                error=f'flash_error: {e}',
            )

        flash_time = time.time() - start_time

        # 置信度足够，直接返回 Flash 结果
        if flash_result['confidence'] >= self.confidence_threshold:
            return DetectionResult(
                file_path=file_path,
                sha256=sha256,
                prediction=flash_result['prediction'],
                confidence=flash_result['confidence'],
                stage='flash',
                features=flash_result['features'],
                processing_time=flash_time,
            )

        # ---------- 第二阶段：Pro ----------
        if self.enable_pro and run_simulation:
            try:
                pro_result = self._pro_detect(file_path)
            except Exception as e:
                logger.exception("Pro 阶段异常")
                return DetectionResult(
                    file_path=file_path,
                    sha256=sha256,
                    prediction=flash_result['prediction'],
                    confidence=flash_result['confidence'],
                    stage='flash',
                    features=flash_result['features'],
                    processing_time=time.time() - start_time,
                    error=f'pro_error: {e}',
                )

            # 模拟失败：回退到 Flash 结果
            if pro_result.get('prediction') == 'uncertain':
                return DetectionResult(
                    file_path=file_path,
                    sha256=sha256,
                    prediction=flash_result['prediction'],
                    confidence=flash_result['confidence'],
                    stage='flash',
                    features=flash_result['features'],
                    processing_time=time.time() - start_time,
                    error=pro_result.get('error'),
                )

            return DetectionResult(
                file_path=file_path,
                sha256=sha256,
                prediction=pro_result['prediction'],
                confidence=pro_result['confidence'],
                stage='pro',
                family=pro_result.get('family'),
                features=pro_result['features'],
                simulation_report=pro_result.get('report'),
                processing_time=time.time() - start_time,
            )

        # 无法进入 Pro：返回 Flash 结果
        return DetectionResult(
            file_path=file_path,
            sha256=sha256,
            prediction=flash_result['prediction'],
            confidence=flash_result['confidence'],
            stage='flash',
            features=flash_result['features'],
            processing_time=flash_time,
        )

    def detect_batch(
        self,
        file_paths: List[str],
        run_simulation: bool = True,
        progress_callback=None,
    ) -> List[DetectionResult]:
        """
        批量检测

        Args:
            file_paths: 文件路径列表
            run_simulation: 是否允许 Pro 模拟
            progress_callback: 可选回调 (current, total, result) -> None
        """
        results: List[DetectionResult] = []
        total = len(file_paths)
        for i, fpath in enumerate(file_paths, 1):
            name = Path(fpath).name
            logger.info("[%d/%d] 检测: %s", i, total, name)
            try:
                result = self.detect(fpath, run_simulation=run_simulation)
            except Exception as e:
                logger.exception("检测异常: %s", fpath)
                result = DetectionResult(
                    file_path=fpath,
                    sha256='',
                    prediction='uncertain',
                    confidence=0.0,
                    stage='flash',
                    processing_time=0.0,
                    error=str(e),
                )
            results.append(result)
            logger.info(
                "  结果: %s (置信度: %.4f, 阶段: %s, 耗时: %.2fs)",
                result.prediction, result.confidence, result.stage, result.processing_time,
            )
            if progress_callback is not None:
                progress_callback(i, total, result)
        return results

    # ----------------------------------
    # Flash 阶段
    # ----------------------------------

    def _flash_detect(self, file_path: str) -> Dict[str, Any]:
        """Flash 阶段：纯静态特征检测"""
        features = self.static_extractor.extract(file_path)
        vector = self.flash_pipeline.vectorizer.vectorize(features).reshape(1, -1)

        prediction = int(self.flash_pipeline.classifier.predict(vector)[0])
        proba = self.flash_pipeline.classifier.predict_proba(vector)[0]

        return {
            'prediction': 'malicious' if prediction == 1 else 'benign',
            'confidence': float(proba[prediction]),
            'features': features,
        }

    # ----------------------------------
    # Pro 阶段
    # ----------------------------------

    def _pro_detect(self, file_path: str) -> Dict[str, Any]:
        """Pro 阶段：模拟 + 行为特征检测"""
        # 1. 运行 Speakeasy 模拟（强制超时）
        report = simulate_with_timeout(file_path, timeout=self.simulation_timeout)
        if report is None:
            return {
                'prediction': 'uncertain',
                'confidence': 0.0,
                'features': {},
                'report': None,
                'error': 'simulation_failed_or_timeout',
            }

        # 2. 提取行为特征
        try:
            behavior_features = self.behavior_extractor.extract(report)
        except Exception as e:
            return {
                'prediction': 'uncertain',
                'confidence': 0.0,
                'features': {},
                'report': None,
                'error': f'behavior_extract_error: {e}',
            }

        # 3. 合并静态特征
        static_features = self.static_extractor.extract(file_path)
        features = {**static_features, **behavior_features}

        # 4. 向量化
        vector = self.pro_pipeline.vectorizer.vectorize(features).reshape(1, -1)

        # 5. 分类预测
        prediction = int(self.pro_pipeline.classifier.predict(vector)[0])
        proba = self.pro_pipeline.classifier.predict_proba(vector)[0]

        # 6. 家族聚类
        family = None
        if self.pro_pipeline.clusterer.model is not None:
            try:
                family_label = int(self.pro_pipeline.clusterer.predict(vector)[0])
                family = self.pro_pipeline.clusterer.family_labels.get(
                    family_label, f'Family_{family_label + 1}'
                )
            except Exception as e:
                logger.debug("家族聚类失败: %s", e)

        return {
            'prediction': 'malicious' if prediction == 1 else 'benign',
            'confidence': float(proba[prediction]),
            'family': family,
            'features': features,
            'report': report,
        }


# ============================================================
# Pro 模型训练入口（带超时模拟）
# ============================================================

def _is_dotnet(file_path: str) -> Optional[bool]:
    """
    快速判断 PE 是否为 .NET 程序集（Speakeasy 无法模拟）

    Returns:
        True: 是 .NET; False: 非 .NET; None: 无法判断
    """
    try:
        import pefile
        pe = pefile.PE(file_path, fast_load=False)
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
                return True
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('ascii', errors='ignore').lower()
                    if 'mscoree' in dll:
                        return True
            return False
        finally:
            pe.close()
    except Exception:
        return None


def train_pro_model(
    malicious_files: List[str],
    benign_files: List[str],
    output_dir: str,
    sample_count: int = 200,
    simulation_timeout: int = 20,
    n_clusters: int = 8,
    cluster_method: str = 'gmm',
    n_pca: int = 15,
    filter_dotnet: bool = True,
) -> Dict[str, Any]:
    """
    训练 Pro 模型（需要运行 Speakeasy 模拟）

    Args:
        malicious_files: 恶意样本路径列表
        benign_files: 良性样本路径列表
        output_dir: 模型输出目录
        sample_count: 每类样本数量（模拟耗时，建议 200 以内）
        simulation_timeout: 单样本模拟超时秒数
        n_clusters: 聚类家族数
        cluster_method: 聚类方法
        n_pca: PCA 降维维度
        filter_dotnet: 是否预过滤 .NET 程序集（Speakeasy 无法模拟）

    Returns:
        训练指标字典
    """
    import random

    random.seed(42)

    # 预过滤 .NET 样本（节省模拟时间）
    # 策略：先从原列表随机抽 3x 样本，再过滤 .NET，避免遍历整个文件池
    if filter_dotnet:
        logger.info("预过滤 .NET 样本（先抽样再过滤）...")
        target_pool_size = sample_count * 3
        malicious_subset = random.sample(
            malicious_files, min(target_pool_size * 2, len(malicious_files))
        )
        benign_subset = random.sample(
            benign_files, min(target_pool_size * 2, len(benign_files))
        )
        malicious_pool = [f for f in malicious_subset if _is_dotnet(f) is False]
        benign_pool = [f for f in benign_subset if _is_dotnet(f) is False]
        logger.info(
            "过滤后池: 恶意=%d/%d, 良性=%d/%d",
            len(malicious_pool), len(malicious_subset),
            len(benign_pool), len(benign_subset),
        )
    else:
        malicious_pool = malicious_files
        benign_pool = benign_files

    malicious_samples = random.sample(
        malicious_pool, min(sample_count, len(malicious_pool))
    )
    benign_samples = random.sample(
        benign_pool, min(sample_count, len(benign_pool))
    )

    logger.info("训练 Pro 模型 (恶意=%d, 良性=%d)", len(malicious_samples), len(benign_samples))

    # 创建 Pipeline
    pipeline = MLPipeline(
        mode='pro',
        n_clusters=n_clusters,
        cluster_method=cluster_method,
        n_pca=n_pca,
    )

    # 批量模拟（带超时）
    reports: Dict[str, Dict[str, Any]] = {}
    all_samples = malicious_samples + benign_samples
    success_count = 0
    fail_count = 0
    start_total = time.time()

    for i, fpath in enumerate(all_samples, 1):
        if i % 20 == 0:
            logger.info("  模拟进度: %d/%d (成功=%d, 失败=%d)",
                        i, len(all_samples), success_count, fail_count)
        report = simulate_with_timeout(fpath, timeout=simulation_timeout)
        if report is not None:
            reports[fpath] = report
            success_count += 1
        else:
            fail_count += 1

    total_time = time.time() - start_total
    logger.info("模拟完成: 成功=%d, 失败=%d, 总耗时=%.0fs",
                success_count, fail_count, total_time)

    # 只用成功模拟的样本训练
    valid_malicious = [f for f in malicious_samples if f in reports]
    valid_benign = [f for f in benign_samples if f in reports]

    if len(valid_malicious) < 10 or len(valid_benign) < 10:
        raise RuntimeError(
            f"有效样本不足 (恶意={len(valid_malicious)}, 良性={len(valid_benign)})"
        )

    # 准备训练数据
    X, y = pipeline.prepare_training_data(valid_malicious, valid_benign, reports=reports)

    # 训练分类器
    metrics = pipeline.train(X, y)

    # 恶意样本聚类
    malicious_X = X[y == 1]
    if len(malicious_X) >= n_clusters:
        pipeline.cluster_malware_families(malicious_X)

    # 保存
    pipeline.save(output_dir)

    logger.info("Pro 模型训练完成: F1=%.4f, 保存到 %s",
                metrics.get('f1', 0.0), output_dir)

    metrics['simulation_success'] = success_count
    metrics['simulation_fail'] = fail_count
    metrics['simulation_total_time'] = total_time
    metrics['valid_malicious'] = len(valid_malicious)
    metrics['valid_benign'] = len(valid_benign)
    return metrics
