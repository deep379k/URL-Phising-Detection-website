"""Train and evaluate the SMS spam NLP pipeline using the UCI corpus."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    make_scorer,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC


ROOT = Path(__file__).resolve().parent
DATASET_PATH = ROOT / "datasets" / "raw" / "sms" / "uci" / "SMSSpamCollection"
MODELS_DIR = ROOT / "models"
MODEL_PATH = MODELS_DIR / "message_spam_pipeline.joblib"
METRICS_PATH = MODELS_DIR / "message_model_metrics.json"
RANDOM_STATE = 42


def models() -> dict[str, object]:
    return {
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.5),
        "Logistic Regression": LogisticRegression(
            class_weight="balanced", max_iter=2_000, random_state=RANDOM_STATE
        ),
        "Linear SVM": LinearSVC(class_weight="balanced", random_state=RANDOM_STATE),
    }


def build_pipeline(classifier: object) -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_df=0.98,
                    sublinear_tf=True,
                    max_features=40_000,
                ),
            ),
            ("classifier", classifier),
        ]
    )


def spam_scores(pipeline: Pipeline, messages: pd.Series):
    if hasattr(pipeline, "predict_proba"):
        return pipeline.predict_proba(messages)[:, list(pipeline.classes_).index("spam")]
    return pipeline.decision_function(messages)


def important_terms(pipeline: Pipeline, limit: int = 20) -> list[dict[str, object]]:
    vectorizer = pipeline.named_steps["tfidf"]
    classifier = pipeline.named_steps["classifier"]
    names = vectorizer.get_feature_names_out()
    if hasattr(classifier, "coef_"):
        weights = classifier.coef_[0]
    elif hasattr(classifier, "feature_log_prob_"):
        weights = classifier.feature_log_prob_[1] - classifier.feature_log_prob_[0]
    else:
        return []
    indices = weights.argsort()[-limit:][::-1]
    return [{"term": str(names[index]), "weight": round(float(weights[index]), 6)} for index in indices]


def train() -> dict[str, object]:
    data = pd.read_csv(
        DATASET_PATH,
        sep="\t",
        names=["label", "message"],
        encoding="utf-8",
        quoting=3,
    )
    original_rows = len(data)
    duplicate_rows = int(data.duplicated().sum())
    data = data.drop_duplicates().copy()

    train_text, test_text, train_y, test_y = train_test_split(
        data["message"],
        data["label"],
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=data["label"],
    )
    folds = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    comparison = {}
    fitted = {}
    spam_average_precision = make_scorer(
        average_precision_score,
        response_method=("decision_function", "predict_proba"),
        pos_label="spam",
    )
    for name, classifier in models().items():
        pipeline = build_pipeline(classifier)
        scores = cross_validate(
            pipeline,
            train_text,
            train_y,
            cv=folds,
            scoring={
                "accuracy": "accuracy",
                "precision": "precision_macro",
                "recall": "recall_macro",
                "f1": "f1_macro",
                "roc_auc": "roc_auc",
                "pr_auc": spam_average_precision,
            },
            n_jobs=-1,
        )
        pipeline.fit(train_text, train_y)
        comparison[name] = {
            metric: round(float(scores[f"test_{metric}"].mean()), 6)
            for metric in ("accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc")
        }
        fitted[name] = pipeline

    selected_name = max(comparison, key=lambda name: (comparison[name]["recall"], comparison[name]["f1"]))
    selected = fitted[selected_name]
    prediction = selected.predict(test_text)
    score = spam_scores(selected, test_text)
    binary_truth = (test_y == "spam").astype(int)
    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "name": "UCI SMS Spam Collection",
            "doi": "10.24432/C5CC84",
            "license": "CC BY 4.0",
            "original_rows": original_rows,
            "duplicate_rows_removed": duplicate_rows,
            "usable_rows": len(data),
            "class_distribution": {str(key): int(value) for key, value in data.label.value_counts().items()},
            "train_rows": len(train_text),
            "test_rows": len(test_text),
        },
        "selected_model": selected_name,
        "selection_rule": "highest mean cross-validation macro recall, then macro F1",
        "cross_validation": comparison,
        "holdout": {
            "accuracy": round(float(accuracy_score(test_y, prediction)), 6),
            "precision_macro": round(float(precision_score(test_y, prediction, average="macro")), 6),
            "recall_macro": round(float(recall_score(test_y, prediction, average="macro")), 6),
            "f1_macro": round(float(f1_score(test_y, prediction, average="macro")), 6),
            "spam_precision": round(float(precision_score(test_y, prediction, pos_label="spam")), 6),
            "spam_recall": round(float(recall_score(test_y, prediction, pos_label="spam")), 6),
            "spam_f1": round(float(f1_score(test_y, prediction, pos_label="spam")), 6),
            "roc_auc": round(float(roc_auc_score(binary_truth, score)), 6),
            "pr_auc": round(float(average_precision_score(binary_truth, score)), 6),
            "confusion_matrix_labels": ["ham", "spam"],
            "confusion_matrix": confusion_matrix(test_y, prediction, labels=["ham", "spam"]).tolist(),
        },
        "important_spam_terms": important_terms(selected),
        "limitations": [
            "The source labels are ham and spam, not phishing or financial fraud.",
            "The corpus is primarily English and does not validate Hindi or Hinglish performance.",
            "Scam themes returned by the application are rule-based indicators, not trained categories.",
        ],
    }
    MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump(selected, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


if __name__ == "__main__":
    print(json.dumps(train(), indent=2))
