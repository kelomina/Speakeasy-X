"""
ML Pipeline：聚类 + 分类
1. 无监督聚类发现恶意软件家族
2. 训练分类器进行二分类（恶意/良性）
3. 支持在线学习（人工调整样本后增量更新）
"""

import json
import pickle
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from collections import Counter

import numpy as np
from sklearn.cluster import KMeans, DBSCAN, MiniBatchKMeans
from sklearn.mixture import GaussianMixture
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, accuracy_score
)
from sklearn.preprocessing import StandardScaler
import joblib

from .feature_extractor import StaticExtractor, BehaviorExtractor, FeatureVectorizer


class MalwareFamilyClusterer:
    """无监督聚类发现恶意软件家族"""

    def __init__(self, n_clusters: int = 10, method: str = 'gmm', n_pca: int = 20):
        """
        n_clusters: 聚类数量（家族数量）
        method: 聚类方法 ('kmeans', 'minibatch', 'gmm', 'dbscan')
        n_pca: PCA降维维度，0表示不降维
        """
        self.n_clusters = n_clusters
        self.method = method
        self.n_pca = n_pca
        self.model = None
        self.scaler = StandardScaler()
        self.pca = None
        self.family_labels = {}  # cluster_id -> family_name

    def fit(self, X: np.ndarray) -> np.ndarray:
        """训练聚类模型"""
        # 标准化
        X_scaled = self.scaler.fit_transform(X)

        # PCA降维（去除噪声维度，保留主要变异）
        if self.n_pca > 0 and self.n_pca < X_scaled.shape[1]:
            self.pca = PCA(n_components=self.n_pca, random_state=42)
            X_reduced = self.pca.fit_transform(X_scaled)
        else:
            X_reduced = X_scaled

        if self.method == 'kmeans':
            self.model = KMeans(n_clusters=self.n_clusters, random_state=42, n_init=10)
            labels = self.model.fit_predict(X_reduced)
        elif self.method == 'minibatch':
            self.model = MiniBatchKMeans(
                n_clusters=self.n_clusters, random_state=42,
                n_init=10, batch_size=100
            )
            labels = self.model.fit_predict(X_reduced)
        elif self.method == 'gmm':
            self.model = GaussianMixture(
                n_components=self.n_clusters, random_state=42,
                covariance_type='diag', n_init=3
            )
            labels = self.model.fit_predict(X_reduced)
        elif self.method == 'dbscan':
            self.model = DBSCAN(eps=0.5, min_samples=5)
            labels = self.model.fit_predict(X_reduced)
        else:
            raise ValueError(f"Unknown method: {self.method}")

        return labels

    def predict(self, X: np.ndarray) -> np.ndarray:
        """预测聚类标签"""
        if self.model is None:
            raise RuntimeError("Model not fitted yet")
        X_scaled = self.scaler.transform(X)
        if self.pca is not None:
            X_scaled = self.pca.transform(X_scaled)
        return self.model.predict(X_scaled)

    def assign_family_names(self, labels: np.ndarray, sample_hashes: List[str]):
        """为聚类分配家族名称"""
        label_counter = Counter(labels)
        for i, (label, count) in enumerate(label_counter.most_common()):
            if label == -1:  # DBSCAN噪声点
                self.family_labels[label] = "Unknown"
            else:
                self.family_labels[label] = f"Family_{i+1}"
        return self.family_labels


class MalwareClassifier:
    """恶意软件分类器（二分类：恶意/良性）"""

    def __init__(self, model_type: str = 'random_forest', **kwargs):
        """
        model_type: 'random_forest' 或 'gradient_boosting'
        """
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.vectorizer = None
        self.metadata = {}

        if model_type == 'random_forest':
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1,
                **kwargs
            )
        elif model_type == 'gradient_boosting':
            self.model = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                random_state=42,
                **kwargs
            )
        else:
            raise ValueError(f"Unknown model type: {model_type}")

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        test_size: float = 0.2,
        cross_validation: bool = True
    ) -> Dict[str, Any]:
        """
        训练分类器
        返回训练指标
        """
        # 标准化
        X_scaled = self.scaler.fit_transform(X)

        # 划分训练集和测试集
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=test_size, random_state=42, stratify=y
        )

        # 训练
        self.model.fit(X_train, y_train)

        # 评估
        y_pred = self.model.predict(X_test)
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1': f1_score(y_test, y_pred, zero_division=0),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
        }

        # 交叉验证
        if cross_validation:
            cv_scores = cross_val_score(self.model, X_scaled, y, cv=5, scoring='f1')
            metrics['cv_f1_mean'] = cv_scores.mean()
            metrics['cv_f1_std'] = cv_scores.std()

        # 特征重要性
        if hasattr(self.model, 'feature_importances_'):
            metrics['feature_importances'] = self.model.feature_importances_.tolist()

        self.metadata = metrics
        return metrics

    def predict(self, X: np.ndarray) -> np.ndarray:
        """预测"""
        if self.model is None:
            raise RuntimeError("Model not trained yet")
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """预测概率"""
        if self.model is None:
            raise RuntimeError("Model not trained yet")
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)

    def partial_fit(self, X: np.ndarray, y: np.ndarray):
        """在线学习：增量更新（仅支持部分模型）"""
        # RandomForest不支持partial_fit，需要重新训练
        # 这里简化处理：保存旧数据，合并后重新训练
        if not hasattr(self, '_training_data'):
            self._training_data = {'X': [], 'y': []}

        self._training_data['X'].append(X)
        self._training_data['y'].append(y)

        # 合并所有数据重新训练
        X_all = np.vstack(self._training_data['X'])
        y_all = np.concatenate(self._training_data['y'])

        X_scaled = self.scaler.fit_transform(X_all)
        self.model.fit(X_scaled, y_all)

    def save(self, path: str):
        """保存模型"""
        data = {
            'model': self.model,
            'scaler': self.scaler,
            'vectorizer': self.vectorizer,
            'metadata': self.metadata,
            'model_type': self.model_type,
        }
        if hasattr(self, '_training_data'):
            data['training_data'] = self._training_data
        joblib.dump(data, path)

    @classmethod
    def load(cls, path: str) -> 'MalwareClassifier':
        """加载模型"""
        data = joblib.load(path)
        classifier = cls(model_type=data['model_type'])
        classifier.model = data['model']
        classifier.scaler = data['scaler']
        classifier.vectorizer = data.get('vectorizer')
        classifier.metadata = data.get('metadata', {})
        if 'training_data' in data:
            classifier._training_data = data['training_data']
        return classifier


class MLPipeline:
    """完整的ML训练和预测流程"""

    def __init__(
        self,
        mode: str = 'flash',
        n_clusters: int = 10,
        model_type: str = 'random_forest',
        cluster_method: str = 'gmm',
        n_pca: int = 20
    ):
        """
        mode: 'flash' 仅静态特征, 'pro' 静态+行为特征
        n_clusters: 聚类数量
        model_type: 分类器类型
        cluster_method: 聚类方法 ('gmm', 'kmeans', 'minibatch', 'dbscan')
        n_pca: PCA降维维度
        """
        self.mode = mode
        self.static_extractor = StaticExtractor()
        self.behavior_extractor = BehaviorExtractor()
        self.vectorizer = FeatureVectorizer(mode=mode)
        self.clusterer = MalwareFamilyClusterer(
            n_clusters=n_clusters, method=cluster_method, n_pca=n_pca
        )
        self.classifier = MalwareClassifier(model_type=model_type)
        self.training_data = []

    def extract_features_from_file(self, file_path: str, report: Any = None) -> Dict[str, Any]:
        """从文件和可选的报告中提取特征"""
        # 静态特征
        features = self.static_extractor.extract(file_path)

        # 行为特征（Pro模式）
        if self.mode == 'pro' and report is not None:
            behavior_features = self.behavior_extractor.extract(report)
            features.update(behavior_features)

        return features

    def prepare_training_data(
        self,
        malicious_files: List[str],
        benign_files: List[str],
        reports: Dict[str, Any] = None
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        准备训练数据
        reports: {file_path: report} 可选的模拟报告
        """
        X_list = []
        y_list = []

        # 恶意样本
        print(f"提取恶意样本特征 ({len(malicious_files)} 个)...")
        for i, fpath in enumerate(malicious_files, 1):
            if i % 100 == 0:
                print(f"  进度: {i}/{len(malicious_files)}")
            report = reports.get(fpath) if reports else None
            features = self.extract_features_from_file(fpath, report)
            vector = self.vectorizer.vectorize(features)
            X_list.append(vector)
            y_list.append(1)  # 恶意=1
            self.training_data.append({
                'file_path': fpath,
                'label': 1,
                'features': features
            })

        # 良性样本
        print(f"提取良性样本特征 ({len(benign_files)} 个)...")
        for i, fpath in enumerate(benign_files, 1):
            if i % 100 == 0:
                print(f"  进度: {i}/{len(benign_files)}")
            report = reports.get(fpath) if reports else None
            features = self.extract_features_from_file(fpath, report)
            vector = self.vectorizer.vectorize(features)
            X_list.append(vector)
            y_list.append(0)  # 良性=0
            self.training_data.append({
                'file_path': fpath,
                'label': 0,
                'features': features
            })

        X = np.array(X_list)
        y = np.array(y_list)
        return X, y

    def train(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """训练模型"""
        print("训练分类器...")
        metrics = self.classifier.train(X, y)
        print(f"训练完成: F1={metrics['f1']:.4f}, Accuracy={metrics['accuracy']:.4f}")
        return metrics

    def cluster_malware_families(self, malicious_X: np.ndarray) -> Dict[int, str]:
        """对恶意样本进行聚类，发现家族"""
        print(f"聚类恶意样本 (n_clusters={self.clusterer.n_clusters})...")
        labels = self.clusterer.fit(malicious_X)
        family_labels = self.clusterer.assign_family_names(labels, [])
        noise_label = -1
        print(f"发现 {len(set(labels) - {noise_label})} 个家族")
        return family_labels

    def predict(self, file_path: str, report: Any = None) -> Dict[str, Any]:
        """预测单个文件"""
        features = self.extract_features_from_file(file_path, report)
        vector = self.vectorizer.vectorize(features)
        vector = vector.reshape(1, -1)

        prediction = self.classifier.predict(vector)[0]
        proba = self.classifier.predict_proba(vector)[0]

        result = {
            'prediction': 'malicious' if prediction == 1 else 'benign',
            'confidence': float(proba[prediction]),
            'features': features
        }

        # Pro模式下进行家族分类
        if self.mode == 'pro' and self.clusterer.model is not None:
            family_label = self.clusterer.predict(vector)[0]
            result['family'] = self.clusterer.family_labels.get(family_label, 'Unknown')

        return result

    def save(self, output_dir: str):
        """保存整个pipeline"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # 保存分类器
        self.classifier.save(str(output_path / 'classifier.pkl'))

        # 保存聚类器
        clusterer_data = {
            'model': self.clusterer.model,
            'scaler': self.clusterer.scaler,
            'pca': self.clusterer.pca,
            'family_labels': self.clusterer.family_labels,
            'n_clusters': self.clusterer.n_clusters,
            'method': self.clusterer.method,
            'n_pca': self.clusterer.n_pca,
        }
        joblib.dump(clusterer_data, str(output_path / 'clusterer.pkl'))

        # 保存元信息
        metadata = {
            'mode': self.mode,
            'vectorizer_features': self.vectorizer.feature_names,
        }
        with open(output_path / 'metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)

        print(f"Pipeline已保存到: {output_dir}")

    @classmethod
    def load(cls, model_dir: str, mode: str = 'flash') -> 'MLPipeline':
        """加载pipeline"""
        model_path = Path(model_dir)

        pipeline = cls(mode=mode)

        # 加载分类器
        pipeline.classifier = MalwareClassifier.load(str(model_path / 'classifier.pkl'))

        # 加载聚类器
        clusterer_data = joblib.load(str(model_path / 'clusterer.pkl'))
        pipeline.clusterer.model = clusterer_data['model']
        pipeline.clusterer.scaler = clusterer_data['scaler']
        pipeline.clusterer.pca = clusterer_data.get('pca')
        pipeline.clusterer.family_labels = clusterer_data['family_labels']
        pipeline.clusterer.n_clusters = clusterer_data['n_clusters']
        pipeline.clusterer.method = clusterer_data['method']
        pipeline.clusterer.n_pca = clusterer_data.get('n_pca', 0)

        print(f"Pipeline已从 {model_dir} 加载")
        return pipeline
