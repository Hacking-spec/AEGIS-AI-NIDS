"""
Model Training and Evaluation Pipeline for Aegis AI-NIDS.
Generates baseline network traffic & attack datasets, trains Supervised Classifiers and PyTorch AutoEncoder,
and exports production weights.
"""
import sys
import os
from pathlib import Path
from typing import Tuple, List, Dict
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score

# Ensure root directory is on Python path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.config import settings, MODELS_DIR
from backend.app.models.ml_detector import MLDetector, FEATURE_COLUMNS
from backend.app.models.anomaly_detector import AnomalyDetector
from backend.app.models.schemas import AttackType


def generate_synthetic_ids_dataset(num_samples: int = 4000) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Synthesizes multi-class network flow records modeled on CIC-IDS2017 & NSL-KDD benchmarks.
    Vectorized for rapid generation and optimal fidelity.
    """
    np.random.seed(42)
    rows = []
    labels = []
    benign_rows = []

    classes = [
        (AttackType.BENIGN.value, 0.40),
        (AttackType.DDOS.value, 0.15),
        (AttackType.PORT_SCAN.value, 0.15),
        (AttackType.BRUTE_FORCE.value, 0.10),
        (AttackType.WEB_ATTACK.value, 0.08),
        (AttackType.C2_BEACON.value, 0.06),
        (AttackType.EXFILTRATION.value, 0.06),
    ]

    for label, ratio in classes:
        n = int(num_samples * ratio)
        if n == 0:
            continue
        
        if label == AttackType.BENIGN.value:
            dur = np.random.uniform(0.1, 2.5, n)
            s_bytes = np.random.uniform(200, 3500, n)
            d_bytes = np.random.uniform(500, 8000, n)
            s_pkts = np.random.randint(4, 25, n)
            d_pkts = np.random.randint(4, 30, n)
            serror = np.random.uniform(0.0, 0.04, n)
            rerror = np.random.uniform(0.0, 0.03, n)
            same_srv = np.random.uniform(0.85, 1.0, n)
            diff_srv = np.random.uniform(0.0, 0.15, n)
            dst_host = np.random.randint(2, 20, n)
            dst_srv = np.random.randint(2, 20, n)
            dst_same = np.random.uniform(0.8, 1.0, n)
            p_tcp = np.ones(n)
            p_udp = np.zeros(n)
            p_icmp = np.zeros(n)
        elif label == AttackType.DDOS.value:
            dur = np.random.uniform(0.01, 0.05, n)
            s_bytes = np.random.uniform(40, 100, n)
            d_bytes = np.zeros(n)
            s_pkts = np.random.randint(300, 1000, n)
            d_pkts = np.zeros(n)
            serror = np.random.uniform(0.85, 1.0, n)
            rerror = np.zeros(n)
            same_srv = np.ones(n)
            diff_srv = np.zeros(n)
            dst_host = np.full(n, 100)
            dst_srv = np.full(n, 100)
            dst_same = np.ones(n)
            p_tcp = np.ones(n)
            p_udp = np.zeros(n)
            p_icmp = np.zeros(n)
        elif label == AttackType.PORT_SCAN.value:
            dur = np.random.uniform(0.01, 0.1, n)
            s_bytes = np.random.uniform(40, 70, n)
            d_bytes = np.random.uniform(0, 30, n)
            s_pkts = np.random.randint(1, 3, n)
            d_pkts = np.random.randint(0, 2, n)
            serror = np.random.uniform(0.1, 0.3, n)
            rerror = np.random.uniform(0.65, 0.95, n)
            same_srv = np.random.uniform(0.02, 0.15, n)
            diff_srv = np.random.uniform(0.85, 1.0, n)
            dst_host = np.random.randint(60, 95, n)
            dst_srv = np.random.randint(1, 4, n)
            dst_same = np.random.uniform(0.01, 0.1, n)
            p_tcp = np.ones(n)
            p_udp = np.zeros(n)
            p_icmp = np.zeros(n)
        elif label == AttackType.BRUTE_FORCE.value:
            dur = np.random.uniform(0.2, 1.0, n)
            s_bytes = np.random.uniform(150, 400, n)
            d_bytes = np.random.uniform(80, 200, n)
            s_pkts = np.random.randint(12, 35, n)
            d_pkts = np.random.randint(10, 30, n)
            serror = np.zeros(n)
            rerror = np.random.uniform(0.75, 0.98, n)
            same_srv = np.ones(n)
            diff_srv = np.zeros(n)
            dst_host = np.ones(n)
            dst_srv = np.ones(n)
            dst_same = np.ones(n)
            p_tcp = np.ones(n)
            p_udp = np.zeros(n)
            p_icmp = np.zeros(n)
        elif label == AttackType.WEB_ATTACK.value:
            dur = np.random.uniform(0.15, 0.8, n)
            s_bytes = np.random.uniform(400, 2200, n)
            d_bytes = np.random.uniform(450, 3000, n)
            s_pkts = np.random.randint(6, 16, n)
            d_pkts = np.random.randint(5, 15, n)
            serror = np.zeros(n)
            rerror = np.random.uniform(0.0, 0.15, n)
            same_srv = np.random.uniform(0.85, 1.0, n)
            diff_srv = np.random.uniform(0.0, 0.15, n)
            dst_host = np.random.randint(2, 8, n)
            dst_srv = np.random.randint(2, 8, n)
            dst_same = np.random.uniform(0.8, 1.0, n)
            p_tcp = np.ones(n)
            p_udp = np.zeros(n)
            p_icmp = np.zeros(n)
        elif label == AttackType.C2_BEACON.value:
            dur = np.random.uniform(1.2, 3.5, n)
            s_bytes = np.random.uniform(250, 700, n)
            d_bytes = np.random.uniform(180, 450, n)
            s_pkts = np.random.randint(6, 14, n)
            d_pkts = np.random.randint(5, 12, n)
            serror = np.zeros(n)
            rerror = np.zeros(n)
            same_srv = np.ones(n)
            diff_srv = np.zeros(n)
            dst_host = np.ones(n)
            dst_srv = np.ones(n)
            dst_same = np.ones(n)
            p_tcp = np.ones(n)
            p_udp = np.zeros(n)
            p_icmp = np.zeros(n)
        elif label == AttackType.EXFILTRATION.value:
            dur = np.random.uniform(15.0, 50.0, n)
            s_bytes = np.random.uniform(8_000_000, 25_000_000, n)
            d_bytes = np.random.uniform(1000, 4000, n)
            s_pkts = np.random.randint(6000, 18000, n)
            d_pkts = np.random.randint(300, 900, n)
            serror = np.zeros(n)
            rerror = np.zeros(n)
            same_srv = np.ones(n)
            diff_srv = np.zeros(n)
            dst_host = np.ones(n)
            dst_srv = np.ones(n)
            dst_same = np.ones(n)
            p_tcp = np.ones(n)
            p_udp = np.zeros(n)
            p_icmp = np.zeros(n)

        safe_dur = np.maximum(dur, 0.001)
        pkt_rate = (s_pkts + d_pkts) / safe_dur
        byte_rate = (s_bytes + d_bytes) / safe_dur

        features = np.column_stack([
            dur, s_bytes, d_bytes, s_pkts, d_pkts,
            serror, rerror, same_srv, diff_srv,
            dst_host, dst_srv, dst_same,
            pkt_rate, byte_rate,
            p_tcp, p_udp, p_icmp
        ])

        rows.append(features)
        labels.extend([label] * n)
        if label == AttackType.BENIGN.value:
            benign_rows.append(features)

    X_all = np.vstack(rows).astype(np.float32)
    y_all = np.array(labels)
    X_benign_all = np.vstack(benign_rows).astype(np.float32)
    return X_all, y_all, X_benign_all


def train_and_evaluate():
    print("=" * 65)
    print("  AEGIS AI-NIDS: TRAINING PRODUCTION DETECTION MODELS")
    print("=" * 65)

    print("[1/4] Generating benchmark network dataset...")
    X, y, X_benign = generate_synthetic_ids_dataset(num_samples=15000)
    print(f"      Total records: {X.shape[0]} | Features per flow: {X.shape[1]}")
    print(f"      Benign baseline samples for AutoEncoder: {X_benign.shape[0]}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 1. Train Supervised Multi-Class Classifier
    print("\n[2/4] Training Supervised Random Forest Classifier...")
    ml_detector = MLDetector()
    ml_detector.fit(X_train, y_train)

    X_test_scaled = ml_detector.scaler.transform(X_test)
    y_pred = ml_detector.model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="weighted")

    print(f"      [✓] Supervised Model Test Accuracy: {acc*100:.2f}% | F1-Score: {f1:.4f}")
    print("\nDetailed Multi-Class Classification Report:")
    print(classification_report(y_test, y_pred, digits=4))

    # Save Supervised Model & Scaler
    ml_detector.save(settings.SUPERVISED_MODEL_PATH, settings.SCALER_PATH)
    print(f"      Saved model to: {settings.SUPERVISED_MODEL_PATH}")
    print(f"      Saved scaler to: {settings.SCALER_PATH}")

    # 2. Train Deep AutoEncoder on Benign Traffic
    print("\n[3/4] Training Neural Network AutoEncoder on Benign Baselines...")
    X_benign_scaled = ml_detector.scaler.transform(X_benign)
    anomaly_detector = AnomalyDetector(input_dim=X.shape[1])
    anomaly_detector.fit(X_benign_scaled)

    anomaly_detector.save(settings.ENCODER_MODEL_PATH)
    print(f"      [✓] Neural AutoEncoder trained. Anomaly Threshold: {anomaly_detector.threshold:.4f}")
    print(f"      Saved AutoEncoder to: {settings.ENCODER_MODEL_PATH}")

    # 3. Test Zero-Day Anomaly Detection
    print("\n[4/4] Verifying Unsupervised Zero-Day Anomaly Detection...")
    # Test on benign
    test_benign_sample = X_benign_scaled[0]
    res_benign = anomaly_detector.predict(test_benign_sample)
    print(f"      Benign Sample Anomaly Score: {res_benign['anomaly_score']} (Flagged: {res_benign['is_anomaly']})")

    # Test on synthetic unknown anomaly
    anomalous_sample = test_benign_sample.copy()
    anomalous_sample[1] *= 50.0  # Spike src_bytes
    anomalous_sample[12] *= 100.0  # Spike packet_rate
    res_anomaly = anomaly_detector.predict(anomalous_sample)
    print(f"      Zero-Day Anomaly Sample Score: {res_anomaly['anomaly_score']} (Flagged: {res_anomaly['is_anomaly']})")

    print("\n" + "=" * 65)
    print("  [SUCCESS] All Models Trained and Exported Successfully!")
    print("=" * 65)


if __name__ == "__main__":
    train_and_evaluate()
