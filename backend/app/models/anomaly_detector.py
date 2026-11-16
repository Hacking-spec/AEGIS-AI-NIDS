"""
Unsupervised Anomaly Detection Engine using Neural Autoencoder & Isolation Forest.
Detects zero-day exploits, unknown attack variants, and baseline traffic deviations.
"""
from pathlib import Path
from typing import Dict, Any, Optional
import numpy as np
import joblib
from sklearn.neural_network import MLPRegressor
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """
    Hybrid Unsupervised Anomaly Detector:
    1. Neural Network Autoencoder (Input -> 32 -> 16 -> 6 -> 16 -> 32 -> Output)
       Learns low-dimensional manifold of benign traffic. Anomalous packets exhibit high reconstruction error.
    2. Isolation Forest:
       Partitions high-dimensional feature space to isolate zero-day anomalies.
    """
    def __init__(self, input_dim: int = 17, threshold: float = 0.65):
        self.input_dim = input_dim
        self.threshold = threshold
        self.autoencoder = MLPRegressor(
            hidden_layer_sizes=(32, 16, 6, 16, 32),
            activation="relu",
            solver="adam",
            learning_rate_init=0.005,
            max_iter=30,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.1
        )
        self.iso_forest = IsolationForest(
            n_estimators=40,
            contamination=0.08,
            random_state=42,
            n_jobs=1
        )
        self.is_trained = False

    def fit(self, X_train: np.ndarray):
        """
        Trains the Autoencoder and Isolation Forest on benign baseline traffic.
        """
        # Autoencoder trains X -> X
        self.autoencoder.fit(X_train, X_train)
        
        # Fit Isolation Forest
        sub_size = min(len(X_train), 2500)
        idx = np.random.choice(len(X_train), size=sub_size, replace=False)
        self.iso_forest.fit(X_train[idx])
        self.is_trained = True

        # Calculate dynamic threshold based on 98th percentile of benign reconstruction MSE
        reconstructed = self.autoencoder.predict(X_train)
        losses = np.mean((X_train - reconstructed) ** 2, axis=1)
        self.threshold = float(np.percentile(losses, 98)) * 1.8

    def predict(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """
        Computes reconstruction error and anomaly score for an input flow.
        """
        if feature_vector.ndim == 1:
            feature_vector = feature_vector.reshape(1, -1)

        if not self.is_trained:
            return {
                "anomaly_score": 0.15,
                "is_anomaly": False,
                "reconstruction_error": 0.08,
                "threshold": self.threshold
            }

        # Autoencoder reconstruction error
        reconstructed = self.autoencoder.predict(feature_vector)
        mse_loss = float(np.mean((feature_vector - reconstructed) ** 2))

        # Normalized sigmoid mapping around threshold
        ratio = mse_loss / max(self.threshold, 1e-4)
        ae_score = 1.0 / (1.0 + np.exp(-2.5 * (ratio - 1.2)))

        # Isolation Forest score
        raw_iso = self.iso_forest.decision_function(feature_vector)[0]
        iso_score = float(np.clip(0.5 - raw_iso, 0.0, 1.0))

        # Ensemble anomaly score (70% AutoEncoder + 30% Isolation Forest)
        fused_score = float(np.clip(0.70 * ae_score + 0.30 * iso_score, 0.0, 1.0))
        is_anomaly = (mse_loss > self.threshold) and (fused_score >= 0.70)

        return {
            "anomaly_score": round(fused_score, 4),
            "is_anomaly": bool(is_anomaly),
            "reconstruction_error": round(mse_loss, 6),
            "threshold": round(self.threshold, 6)
        }

    def save(self, filepath: Path):
        """Saves model weights."""
        joblib.dump({
            "autoencoder": self.autoencoder,
            "iso_forest": self.iso_forest,
            "threshold": self.threshold,
            "input_dim": self.input_dim
        }, filepath)

    def load(self, filepath: Path) -> bool:
        """Loads weights from disk."""
        if not filepath.exists():
            return False
        try:
            data = joblib.load(filepath)
            self.autoencoder = data["autoencoder"]
            self.iso_forest = data["iso_forest"]
            if hasattr(self.iso_forest, "n_jobs"):
                self.iso_forest.n_jobs = 1
            self.threshold = data["threshold"]
            self.input_dim = data.get("input_dim", self.input_dim)
            self.is_trained = True
            return True
        except Exception as e:
            print(f"Error loading anomaly detector: {e}")
            return False
