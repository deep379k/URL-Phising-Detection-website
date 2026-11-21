"""Train, compare, evaluate, and save the PhishGuard URL model."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier

from url_features import FEATURE_NAMES


ROOT = Path(__file__).resolve().parent
DATASET_PATH = ROOT / "phishing.csv"
MODELS_DIR = ROOT / "models"
MODEL_PATH = MODELS_DIR / "url_phishing_pipeline.joblib"
METRICS_PATH = MODELS_DIR / "url_model_metrics.json"
RANDOM_STATE = 42


def _models() -> dict[str, object]:
    return {
        "Logistic Regression": LogisticRegression(
            class_weight="balanced", max_iter=2_000, random_state=RANDOM_STATE
        ),
        "Decision Tree": DecisionTreeClassifier(
            class_weight="balanced", max_depth=10, min_samples_leaf=4, random_state=RANDOM_STATE
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced",
            min_samples_leaf=2,
            n_jobs=-1,
            random_state=RANDOM_STATE,
        ),
        "Gradient Boosting": GradientBoostingClassifier(random_state=RANDOM_STATE),
    }


def _phishing_scores(model: object, features: pd.DataFrame) -> list[float]:
    classes = list(model.classes_)
    phishing_index = classes.index(-1)
    if hasattr(model, "predict_proba"):
        return model.predict_proba(features)[:, phishing_index]
    scores = model.decision_function(features)
    return -scores if classes[-1] == 1 else scores


def train() -> dict[str, object]:
    data = pd.read_csv(DATASET_PATH)
    original_rows = len(data)
    data = data.drop_duplicates(subset=FEATURE_NAMES + ["class"]).copy()
    data = data.dropna(subset=FEATURE_NAMES + ["class"])

    features = data[FEATURE_NAMES].astype(int)
    target = data["class"].astype(int)
    train_x, test_x, train_y, test_y = train_test_split(
        features,
        target,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=target,
    )

    cross_validation = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    comparison: dict[str, dict[str, float]] = {}
    fitted: dict[str, object] = {}

    for name, estimator in _models().items():
        pipeline = Pipeline([("classifier", estimator)])
        scores = cross_validate(
            pipeline,
            train_x,
            train_y,
            cv=cross_validation,
            scoring={
                "accuracy": "accuracy",
                "precision": "precision_macro",
                "recall": "recall_macro",
                "f1": "f1_macro",
            },
            n_jobs=-1,
        )
        pipeline.fit(train_x, train_y)
        comparison[name] = {
            metric: round(float(scores[f"test_{metric}"].mean()), 6)
            for metric in ("accuracy", "precision", "recall", "f1")
        }
        fitted[name] = pipeline

    # Prefer phishing recall, then macro F1. False negatives are the costliest error.
    selected_name = max(
        comparison,
        key=lambda name: (comparison[name]["recall"], comparison[name]["f1"]),
    )
    selected = fitted[selected_name]
    prediction = selected.predict(test_x)
    phishing_probability = _phishing_scores(selected, test_x)
    binary_truth = (test_y == -1).astype(int)

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "source": DATASET_PATH.name,
            "original_rows": original_rows,
            "usable_unique_rows": len(data),
            "features": FEATURE_NAMES,
            "class_distribution": {str(key): int(value) for key, value in target.value_counts().items()},
            "train_rows": len(train_x),
            "test_rows": len(test_x),
        },
        "selected_model": selected_name,
        "selection_rule": "highest mean cross-validation macro recall, then macro F1",
        "cross_validation": comparison,
        "holdout": {
            "accuracy": round(float(accuracy_score(test_y, prediction)), 6),
            "precision_macro": round(float(precision_score(test_y, prediction, average="macro")), 6),
            "recall_macro": round(float(recall_score(test_y, prediction, average="macro")), 6),
            "f1_macro": round(float(f1_score(test_y, prediction, average="macro")), 6),
            "phishing_recall": round(float(recall_score(binary_truth, prediction == -1)), 6),
            "roc_auc": round(float(roc_auc_score(binary_truth, phishing_probability)), 6),
            "pr_auc": round(float(average_precision_score(binary_truth, phishing_probability)), 6),
            "confusion_matrix_labels": [-1, 1],
            "confusion_matrix": confusion_matrix(test_y, prediction, labels=[-1, 1]).tolist(),
        },
    }

    MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump(selected, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


if __name__ == "__main__":
    result = train()
    print(json.dumps(result, indent=2))

