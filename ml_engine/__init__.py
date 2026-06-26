"""
Speakeasy-X ML Engine
机器学习病毒识别引擎

- StaticExtractor: 静态特征提取（Flash 模式）
- BehaviorExtractor: 行为特征提取（Pro 模式，需 Speakeasy 模拟报告）
- FeatureVectorizer: 特征向量化
- MLPipeline: 训练 + 推理 pipeline
- MalwareClassifier: 二分类器
- MalwareFamilyClusterer: 恶意软件家族聚类器
- TwoStageDetector: 两阶段检测引擎（Flash + Pro）
- DetectionResult: 检测结果数据类
"""

from .feature_extractor import StaticExtractor, BehaviorExtractor, FeatureVectorizer
from .dotnet_extractor import DotNetExtractor
from .ml_pipeline import MLPipeline, MalwareClassifier, MalwareFamilyClusterer
from .detection_engine import (
    TwoStageDetector,
    DetectionResult,
    simulate_with_timeout,
    train_pro_model,
)

__all__ = [
    'StaticExtractor',
    'BehaviorExtractor',
    'FeatureVectorizer',
    'DotNetExtractor',
    'MLPipeline',
    'MalwareClassifier',
    'MalwareFamilyClusterer',
    'TwoStageDetector',
    'DetectionResult',
    'simulate_with_timeout',
    'train_pro_model',
]
