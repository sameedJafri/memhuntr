# memhuntr

A memory forensics malware classifier that uses Volatility 3 plugin outputs and a two-stage XGBoost pipeline to classify Windows memory dumps as **Benign** or **Malware** (Ransomware, Spyware, or Trojan).

## How It Works

memhuntr extracts 39 behavioral features from a memory dump by running 8 Volatility 3 plugins (`windows.pslist`, `windows.dlllist`, `windows.handles`, `windows.ldrmodules`, `windows.malfind`, `windows.psxview`, `windows.svcscan`, `windows.callbacks`), then feeds them through a two-stage classifier:

1. **Stage 1** — Binary classification (Benign vs Malware)
2. **Stage 2** — Malware subtype classification (Ransomware / Spyware / Trojan)

Both stages use XGBoost models trained on the [MalMem-2024](https://www.sciencedirect.com/science/article/pii/S0167404824001652) dataset with a temporal train/test split.

## Project Structure

```
memhuntr/
├── src/
│   ├── cli.py            # Typer CLI (scan, info, check)
│   ├── extraction.py     # Volatility plugin runners and output parsers
│   └── inference.py      # Model loading, prediction, and explanation
├── tests/
│   ├── test_cli.py       # CLI command tests
│   ├── test_extraction.py
│   └── test_inference.py
├── notebooks/
│   ├── 01_EDA_and_cleaning.ipynb
│   ├── 02_feature_engineering.ipynb
│   └── 03_model_training_evaluation.ipynb
├── data/
│   ├── raw/              # Original benign and malware CSV datasets
│   └── processed/        # Engineered features, scalers, and trained models
│       ├── temporal/     # Temporal split artifacts (default)
│       └── random/       # Random split artifacts
└── requirements.txt
```

## Prerequisites

- **Python 3.10+**
- **Volatility 3** — install with `pip install volatility3` or from [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3). Ensure `vol` is on your PATH (or pass `--vol-path`)
- A Windows memory dump (`.raw`, `.vmem`, etc.)

## Installation

```bash
git clone https://github.com/<your-username>/memhuntr.git
cd memhuntr

python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

pip install -r requirements.txt
```

## Usage

### Check setup

Verify that Volatility 3 and model files are available:

```bash
python -m src.cli check
```

### Detect OS info

Get OS information for a memory dump (Volatility 3 auto-detects the profile):

```bash
python -m src.cli info /path/to/dump.raw
```

### Scan a memory dump

```bash
python -m src.cli scan /path/to/dump.raw
```

With JSON output and feature explanations:

```bash
python -m src.cli scan /path/to/dump.raw --output json --explain
```

### CLI Options

| Option | Description |
|---|---|
| `--model-dir`, `-m` | Override model directory |
| `--vol-path` | Path to `vol` executable (default: `vol`) |
| `--output`, `-o` | Output format: `table` or `json` |
| `--explain`, `-e` | Show top features driving the prediction |
| `--timeout`, `-t` | Max seconds per Volatility plugin (default: 600) |

## Reproducing the Models

The notebooks walk through the full pipeline:

1. **01_EDA_and_cleaning** — Exploratory data analysis, outlier removal, class distribution
2. **02_feature_engineering** — Feature selection, correlation filtering, log1p transforms, scaling
3. **03_model_training_evaluation** — Model comparison, two-stage XGBoost training, temporal evaluation

Pre-trained model artifacts are included under `data/processed/temporal/`.

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## Features Extracted

The 39 features span 8 Volatility plugins:

| Plugin | Features |
|---|---|
| `pslist` | Process count, unique parent PIDs, avg threads |
| `dlllist` | Avg DLLs per process |
| `handles` | Total handles, avg per process, counts by type (Desktop, Key, Thread, etc.) |
| `ldrmodules` | Modules not in load/init/mem lists |
| `malfind` | Injection count, commit charge, protection types, unique injections |
| `psxview` | Hidden process indicators across 6 views + false averages |
| `svcscan` | Service counts by type (kernel driver, own process, shared), active count |
| `callbacks` | Total registered callbacks |
