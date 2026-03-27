# memhuntr

A memory forensics malware classifier that uses Volatility 2 plugin outputs and a two-stage XGBoost pipeline to classify Windows memory dumps as **Benign** or **Malware** (Ransomware, Spyware, or Trojan).

## How It Works

memhuntr extracts 39 behavioral features from a memory dump by running 8 Volatility 2 plugins (`pslist`, `dlllist`, `handles`, `ldrmodules`, `malfind`, `psxview`, `svcscan`, `callbacks`), then feeds them through a two-stage classifier:

1. **Stage 1** — Binary classification (Benign vs Malware)
2. **Stage 2** — Malware subtype classification (Ransomware / Spyware / Trojan)

Both stages use XGBoost models trained on the [CIC-MalMem-2022](https://www.unb.ca/cic/datasets/malmem-2022.html) dataset with a temporal train/test split.

## Project Structure

```
memhuntr/
├── src/
│   ├── cli.py            # Typer CLI (scan, imageinfo, check)
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
- **Volatility 2** — install from [volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility) and ensure `vol.py` is on your PATH (or pass `--vol-path`)
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

Verify that Volatility 2 and model files are available:

```bash
python -m src.cli check
```

### Detect OS profile

If you don't know the Volatility profile for your memory dump:

```bash
python -m src.cli imageinfo /path/to/dump.raw
```

### Scan a memory dump

```bash
python -m src.cli scan /path/to/dump.raw --profile Win7SP1x64
```

With JSON output and feature explanations:

```bash
python -m src.cli scan /path/to/dump.raw -p Win7SP1x64 --output json --explain
```

### CLI Options

| Option | Description |
|---|---|
| `--profile`, `-p` | Volatility 2 profile (required for `scan`) |
| `--model-dir`, `-m` | Override model directory |
| `--vol-path` | Path to `vol.py` (default: `vol.py`) |
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
