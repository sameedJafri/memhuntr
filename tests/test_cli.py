"""Tests for CLI module — Typer commands via CliRunner."""

from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest
from typer.testing import CliRunner

from src.cli import app
from src.extraction import FEATURE_ORDER

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_features_df():
    row = {feat: 1.0 for feat in FEATURE_ORDER}
    return pd.DataFrame([row], columns=FEATURE_ORDER)


def _make_mock_pipeline(label="Malware"):
    stage1_pred = 1 if label == "Malware" else 0
    stage1_proba = np.array([0.1, 0.9]) if label == "Malware" else np.array([0.95, 0.05])

    stage1 = MagicMock()
    stage1.predict.return_value = np.array([stage1_pred])
    stage1.predict_proba.return_value = np.array([stage1_proba])
    stage1.feature_importances_ = np.random.rand(len(FEATURE_ORDER))

    stage2 = MagicMock()
    stage2.predict.return_value = np.array([0])
    stage2.predict_proba.return_value = np.array([[0.7, 0.2, 0.1]])
    stage2.feature_importances_ = np.random.rand(len(FEATURE_ORDER))

    le_mal = MagicMock()
    le_mal.inverse_transform.return_value = np.array(["Ransomware"])
    le_mal.classes_ = np.array(["Ransomware", "Spyware", "Trojan"])

    scaler = MagicMock()
    scaler.transform.return_value = np.zeros((1, len(FEATURE_ORDER)))

    return {"stage1": stage1, "stage2": stage2, "le_mal": le_mal, "scaler": scaler}


# ---------------------------------------------------------------------------
# scan command tests
# ---------------------------------------------------------------------------

class TestScanCommand:
    @patch("src.cli.extract_features")
    @patch("src.cli.load_pipeline")
    @patch("src.cli.check_volatility")
    def test_scan_malware_table(self, mock_vol, mock_load, mock_extract, tmp_path):
        dump = tmp_path / "test.raw"
        dump.write_bytes(b"\x00" * 100)

        mock_vol.return_value = "vol.py"
        mock_load.return_value = _make_mock_pipeline("Malware")
        mock_extract.return_value = _make_features_df()

        result = runner.invoke(app, [
            "scan", str(dump), "--profile", "Win7SP1x64"
        ])
        assert result.exit_code == 0
        assert "MALWARE" in result.output

    @patch("src.cli.extract_features")
    @patch("src.cli.load_pipeline")
    @patch("src.cli.check_volatility")
    def test_scan_benign_table(self, mock_vol, mock_load, mock_extract, tmp_path):
        dump = tmp_path / "test.raw"
        dump.write_bytes(b"\x00" * 100)

        mock_vol.return_value = "vol.py"
        mock_load.return_value = _make_mock_pipeline("Benign")
        mock_extract.return_value = _make_features_df()

        result = runner.invoke(app, [
            "scan", str(dump), "--profile", "Win7SP1x64"
        ])
        assert result.exit_code == 0
        assert "BENIGN" in result.output

    @patch("src.cli.extract_features")
    @patch("src.cli.load_pipeline")
    @patch("src.cli.check_volatility")
    def test_scan_json_output(self, mock_vol, mock_load, mock_extract, tmp_path):
        dump = tmp_path / "test.raw"
        dump.write_bytes(b"\x00" * 100)

        mock_vol.return_value = "vol.py"
        mock_load.return_value = _make_mock_pipeline("Malware")
        mock_extract.return_value = _make_features_df()

        result = runner.invoke(app, [
            "scan", str(dump), "--profile", "Win7SP1x64", "--output", "json"
        ])
        assert result.exit_code == 0
        assert '"label"' in result.output
        assert '"Malware"' in result.output

    @patch("src.cli.check_volatility")
    def test_scan_volatility_not_found(self, mock_vol, tmp_path):
        dump = tmp_path / "test.raw"
        dump.write_bytes(b"\x00" * 100)

        mock_vol.side_effect = RuntimeError("Volatility 2 not found")

        result = runner.invoke(app, [
            "scan", str(dump), "--profile", "Win7SP1x64"
        ])
        assert result.exit_code == 1

    @patch("src.cli.load_pipeline")
    @patch("src.cli.check_volatility")
    def test_scan_model_not_found(self, mock_vol, mock_load, tmp_path):
        dump = tmp_path / "test.raw"
        dump.write_bytes(b"\x00" * 100)

        mock_vol.return_value = "vol.py"
        mock_load.side_effect = FileNotFoundError("Model file not found")

        result = runner.invoke(app, [
            "scan", str(dump), "--profile", "Win7SP1x64"
        ])
        assert result.exit_code == 1

    @patch("src.cli.extract_features")
    @patch("src.cli.load_pipeline")
    @patch("src.cli.check_volatility")
    def test_scan_with_explain(self, mock_vol, mock_load, mock_extract, tmp_path):
        dump = tmp_path / "test.raw"
        dump.write_bytes(b"\x00" * 100)

        mock_vol.return_value = "vol.py"
        mock_load.return_value = _make_mock_pipeline("Malware")
        mock_extract.return_value = _make_features_df()

        result = runner.invoke(app, [
            "scan", str(dump), "--profile", "Win7SP1x64", "--explain"
        ])
        assert result.exit_code == 0
        assert "Top Features" in result.output


# ---------------------------------------------------------------------------
# check command tests
# ---------------------------------------------------------------------------

class TestCheckCommand:
    @patch("src.cli.load_pipeline")
    @patch("src.cli.check_volatility")
    def test_check_all_ok(self, mock_vol, mock_load):
        mock_vol.return_value = "vol.py"
        mock_load.return_value = {}

        result = runner.invoke(app, ["check"])
        assert result.exit_code == 0
        assert "Volatility 2" in result.output
        assert "Model files" in result.output

    @patch("src.cli.load_pipeline")
    @patch("src.cli.check_volatility")
    def test_check_vol_missing(self, mock_vol, mock_load):
        mock_vol.side_effect = RuntimeError("not found")
        mock_load.return_value = {}

        result = runner.invoke(app, ["check"])
        assert result.exit_code == 0  # check doesn't exit with error
        assert "not found" in result.output

    @patch("src.cli.load_pipeline")
    @patch("src.cli.check_volatility")
    def test_check_model_missing(self, mock_vol, mock_load):
        mock_vol.return_value = "vol.py"
        mock_load.side_effect = FileNotFoundError("missing")

        result = runner.invoke(app, ["check"])
        assert result.exit_code == 0
        assert "missing" in result.output


# ---------------------------------------------------------------------------
# no-args shows help
# ---------------------------------------------------------------------------

class TestAppHelp:
    def test_no_args_shows_help(self):
        result = runner.invoke(app, [])
        # Typer uses exit code 2 for no_args_is_help
        assert result.exit_code == 0 or result.exit_code == 2
        assert "memhuntr" in result.output.lower() or "Usage" in result.output
