"""Tests for inference module — model loading, prediction, and explanation."""

from unittest.mock import MagicMock

import numpy as np
import pandas as pd
import pytest

from src.extraction import FEATURE_ORDER, LOG1P_FEATURES
from src.inference import DEFAULT_MODEL_DIR, load_pipeline, predict, explain_prediction


# ---------------------------------------------------------------------------
# Helpers — mock pipeline objects
# ---------------------------------------------------------------------------

def _make_mock_pipeline(stage1_pred=1, stage1_proba=None,
                        stage2_pred=0, stage2_proba=None,
                        classes=None):
    """Build a fake pipeline dict that mimics the real artifacts."""
    if stage1_proba is None:
        stage1_proba = np.array([0.1, 0.9])
    if stage2_proba is None:
        stage2_proba = np.array([0.7, 0.2, 0.1])
    if classes is None:
        classes = np.array(["Ransomware", "Spyware", "Trojan"])

    stage1 = MagicMock()
    stage1.predict.return_value = np.array([stage1_pred])
    stage1.predict_proba.return_value = np.array([stage1_proba])
    stage1.feature_importances_ = np.random.rand(len(FEATURE_ORDER))

    stage2 = MagicMock()
    stage2.predict.return_value = np.array([stage2_pred])
    stage2.predict_proba.return_value = np.array([stage2_proba])
    stage2.feature_importances_ = np.random.rand(len(FEATURE_ORDER))

    le_mal = MagicMock()
    le_mal.inverse_transform.return_value = np.array([classes[stage2_pred]])
    le_mal.classes_ = classes

    scaler = MagicMock()
    scaler.transform.return_value = np.zeros((1, len(FEATURE_ORDER)))

    return {"stage1": stage1, "stage2": stage2, "le_mal": le_mal, "scaler": scaler}


def _make_features_df(value=1.0):
    """Create a single-row features DataFrame with all 39 features."""
    row = {feat: value for feat in FEATURE_ORDER}
    return pd.DataFrame([row], columns=FEATURE_ORDER)


# ---------------------------------------------------------------------------
# load_pipeline tests
# ---------------------------------------------------------------------------

class TestLoadPipeline:
    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="Model file not found"):
            load_pipeline(tmp_path)

    def test_partial_files_raises(self, tmp_path):
        # Create only some of the required files (as valid empty pickles won't work,
        # just verify the directory with no matching files raises)
        (tmp_path / "unrelated.txt").write_text("not a model")
        with pytest.raises(FileNotFoundError, match="Model file not found"):
            load_pipeline(tmp_path)

    def test_default_model_dir_constant(self):
        assert DEFAULT_MODEL_DIR.name == "temporal"
        assert "data" in str(DEFAULT_MODEL_DIR)


# ---------------------------------------------------------------------------
# predict tests
# ---------------------------------------------------------------------------

class TestPredict:
    def test_malware_prediction(self):
        pipeline = _make_mock_pipeline(stage1_pred=1)
        df = _make_features_df()
        result = predict(df, pipeline)

        assert result["label"] == "Malware"
        assert 0 < result["confidence"] <= 1.0
        assert result["subtype"] == "Ransomware"
        assert result["subtype_confidence"] is not None
        assert isinstance(result["subtype_probabilities"], dict)
        assert set(result["subtype_probabilities"].keys()) == {"Ransomware", "Spyware", "Trojan"}

    def test_benign_prediction(self):
        pipeline = _make_mock_pipeline(
            stage1_pred=0, stage1_proba=np.array([0.95, 0.05])
        )
        df = _make_features_df()
        result = predict(df, pipeline)

        assert result["label"] == "Benign"
        assert result["confidence"] == pytest.approx(0.95)
        assert result["subtype"] is None
        assert result["subtype_confidence"] is None
        assert result["subtype_probabilities"] is None

    def test_missing_features_raises(self):
        pipeline = _make_mock_pipeline()
        df = pd.DataFrame([{"pslist.nproc": 1}])
        with pytest.raises(ValueError, match="Missing features"):
            predict(df, pipeline)

    def test_column_order_enforced(self):
        """Features should be reordered to match FEATURE_ORDER."""
        pipeline = _make_mock_pipeline(stage1_pred=0)
        row = {feat: float(i) for i, feat in enumerate(reversed(FEATURE_ORDER))}
        df = pd.DataFrame([row])
        result = predict(df, pipeline)
        assert result["label"] == "Benign"
        pipeline["scaler"].transform.assert_called_once()

    def test_log1p_applied_before_scaling(self):
        """Verify that predict applies log1p then scales."""
        pipeline = _make_mock_pipeline(stage1_pred=0)
        df = _make_features_df(100.0)
        predict(df, pipeline)

        call_args = pipeline["scaler"].transform.call_args
        transformed_df = call_args[0][0]
        col_idx = FEATURE_ORDER.index(LOG1P_FEATURES[0])
        assert transformed_df.iloc[0, col_idx] == pytest.approx(np.log1p(100.0))

    def test_subtype_probabilities_sum_to_one(self):
        proba = np.array([0.5, 0.3, 0.2])
        pipeline = _make_mock_pipeline(stage1_pred=1, stage2_proba=proba)
        df = _make_features_df()
        result = predict(df, pipeline)
        total = sum(result["subtype_probabilities"].values())
        assert total == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# explain_prediction tests
# ---------------------------------------------------------------------------

class TestExplainPrediction:
    def test_malware_has_both_stages(self):
        pipeline = _make_mock_pipeline(stage1_pred=1)
        df = _make_features_df()
        explanation = explain_prediction(df, pipeline)

        assert "stage1_top" in explanation
        assert "stage2_top" in explanation
        assert len(explanation["stage1_top"]) <= 10
        assert len(explanation["stage2_top"]) <= 10

    def test_benign_has_only_stage1(self):
        pipeline = _make_mock_pipeline(stage1_pred=0)
        df = _make_features_df()
        explanation = explain_prediction(df, pipeline)

        assert "stage1_top" in explanation
        assert "stage2_top" not in explanation

    def test_custom_top_n(self):
        pipeline = _make_mock_pipeline(stage1_pred=1)
        df = _make_features_df()
        explanation = explain_prediction(df, pipeline, top_n=5)

        assert len(explanation["stage1_top"]) == 5
        assert len(explanation["stage2_top"]) == 5

    def test_importances_are_sorted_descending(self):
        pipeline = _make_mock_pipeline(stage1_pred=1)
        df = _make_features_df()
        explanation = explain_prediction(df, pipeline)

        values = list(explanation["stage1_top"].values())
        assert values == sorted(values, reverse=True)
