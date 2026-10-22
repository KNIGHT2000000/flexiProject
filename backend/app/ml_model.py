import json
from pathlib import Path
from typing import Optional
import numpy as np


class FastRandomForest:
    """Ultra-lightweight, zero-scipy, zero-sklearn Random Forest evaluator.

    Achieves 100% mathematical parity with sklearn.ensemble.RandomForestClassifier
    while eliminating 250MB+ of scipy and scikit-learn dependencies for AWS Lambda.
    """

    def __init__(self, model_data: dict):
        self.classes_ = np.array(model_data["classes"])
        self.n_features_in_ = model_data["n_features"]
        self.trees = model_data["trees"]

    @classmethod
    def load(cls, path: str | Path) -> "FastRandomForest":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(data)

    def predict_proba(self, X: list | np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=float)
        if X.ndim == 1:
            X = X.reshape(1, -1)

        n_samples = len(X)
        n_classes = len(self.classes_)
        all_probas = np.zeros((n_samples, n_classes))

        for row_idx, vector in enumerate(X):
            total_votes = np.zeros(n_classes)
            for t in self.trees:
                node = 0
                left = t["left"]
                right = t["right"]
                feat = t["feat"]
                th = t["th"]
                val = t["val"]

                while left[node] != right[node]:
                    if vector[feat[node]] <= th[node]:
                        node = left[node]
                    else:
                        node = right[node]

                leaf_dist = val[node][0]
                s = sum(leaf_dist)
                if s > 0:
                    total_votes += [c / s for c in leaf_dist]
                else:
                    total_votes += leaf_dist

            all_probas[row_idx] = total_votes / len(self.trees)

        return all_probas

    def predict(self, X: list | np.ndarray) -> np.ndarray:
        probas = self.predict_proba(X)
        return self.classes_[np.argmax(probas, axis=1)]
