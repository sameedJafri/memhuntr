"""Load serialized models and return predictions with confidence scores."""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .extraction import FEATURE_ORDER, apply_log1p

# Default model directory (temporal split, two-stage weighted)
DEFAULT_MODEL_DIR = Path(__file__).resolve().parent.parent / "data" / "processed" / "temporal"


def load_pipeline(model_dir: Path = None) -> dict:
    """Load the two-stage model pipeline from disk.

    Returns:
        Dict with keys: stage1, stage2, le_mal, scaler.
    """
    model_dir = Path(model_dir) if model_dir else DEFAULT_MODEL_DIR

    required = {
        "stage1": "two_stage_stage1.pkl",
        "stage2": "two_stage_stage2.pkl",
        "le_mal": "two_stage_le_mal.pkl",
        "scaler": "scaler.pkl",
    }

    pipeline = {}
    for key, filename in required.items():
        path = model_dir / filename
        if not path.exists():
            raise FileNotFoundError(
                f"Model file not found: {path}\n"
                f"Run notebook 03 to generate model artifacts."
            )
        pipeline[key] = joblib.load(path)

    return pipeline


def predict(features_df: pd.DataFrame, pipeline: dict) -> dict:
    """Run the two-stage prediction pipeline.

    Args:
        features_df: Raw single-row DataFrame with 39 features (pre-log1p).
        pipeline: Dict from load_pipeline().

    Returns:
        Dict with: label, confidence, subtype, subtype_confidence, subtype_probabilities.
    """
    # Validate columns
    missing = set(FEATURE_ORDER) - set(features_df.columns)
    if missing:
        raise ValueError(f"Missing features: {missing}")

    # Ensure correct column order
    features_df = features_df[FEATURE_ORDER]

    # Apply log1p transform then scale (matches notebook 02 pipeline)
    transformed = apply_log1p(features_df)
    scaled = pd.DataFrame(
        pipeline["scaler"].transform(transformed),
        columns=FEATURE_ORDER,
    )

    # Stage 1: Benign vs Malware
    stage1_pred = pipeline["stage1"].predict(scaled)[0]
    stage1_proba = pipeline["stage1"].predict_proba(scaled)[0]

    if stage1_pred == 0:
        return {
            "label": "Benign",
            "confidence": float(stage1_proba[0]),
            "subtype": None,
            "subtype_confidence": None,
            "subtype_probabilities": None,
        }

    # Stage 2: Malware subtype
    stage2_pred = pipeline["stage2"].predict(scaled)[0]
    stage2_proba = pipeline["stage2"].predict_proba(scaled)[0]

    subtype = pipeline["le_mal"].inverse_transform([stage2_pred])[0]
    subtype_probs = {
        name: float(prob)
        for name, prob in zip(pipeline["le_mal"].classes_, stage2_proba)
    }

    return {
        "label": "Malware",
        "confidence": float(stage1_proba[1]),
        "subtype": subtype,
        "subtype_confidence": float(stage2_proba[stage2_pred]),
        "subtype_probabilities": subtype_probs,
    }


def explain_prediction(features_df: pd.DataFrame, pipeline: dict,
                       top_n: int = 10) -> dict:
    """Identify top features driving the prediction.

    Returns:
        Dict with: stage1_top (feature importance for binary decision),
                   stage2_top (feature importance for subtype, if malware).
    """
    result = {}

    # Stage 1 feature importances
    importances = pipeline["stage1"].feature_importances_
    feat_imp = sorted(
        zip(FEATURE_ORDER, importances), key=lambda x: x[1], reverse=True
    )
    result["stage1_top"] = {name: float(imp) for name, imp in feat_imp[:top_n]}

    # Stage 2 importances (only meaningful if predicted as malware)
    transformed = apply_log1p(features_df[FEATURE_ORDER])
    scaled = pd.DataFrame(
        pipeline["scaler"].transform(transformed),
        columns=FEATURE_ORDER,
    )
    stage1_pred = pipeline["stage1"].predict(scaled)[0]

    if stage1_pred == 1:
        importances2 = pipeline["stage2"].feature_importances_
        feat_imp2 = sorted(
            zip(FEATURE_ORDER, importances2), key=lambda x: x[1], reverse=True
        )
        result["stage2_top"] = {name: float(imp) for name, imp in feat_imp2[:top_n]}

    return result
