# Threat Intelligence System Project

A Flask-based endpoint monitoring dashboard that collects local system metrics, flags possible anomalies with an Isolation Forest model, correlates selected metrics with heuristic MITRE ATT&CK rules, and displays alerts.

> **Prototype notice:** This project is intended for local development and demonstration. Its thresholds and ATT&CK mappings are heuristics, not proof of malicious activity or reliable zero-day detection. Do not rely on it as a production security product.

## Features

- Collects CPU and memory utilization, process count, network I/O counters, and disk I/O counters using `psutil`.
- Applies a saved scikit-learn Isolation Forest model to collected metrics when `iso_forest.pkl` is available.
- Applies simple metric-based rules labeled with selected MITRE ATT&CK techniques.
- Serves a live dashboard and JSON metrics endpoint with Flask.
- Supports operator registration and login, storing registered passwords as hashes in a local SQLite database.
- Includes a separate controlled CPU-load script for demonstrating the correlation rules.

## Requirements

- Python 3.10 or later recommended.
- Dependencies listed in [`requirements.txt`](requirements.txt).

## Setup

Run these commands from the project directory.

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run the dashboard

Set a unique Flask session secret before starting the application.

### Windows PowerShell

```powershell
$env:FLASK_SECRET_KEY = "replace-with-a-long-random-secret"
python app.py
```

### macOS or Linux

```bash
export FLASK_SECRET_KEY="replace-with-a-long-random-secret"
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). Register an operator account or use the configured dashboard fallback credentials. The current development defaults are `admin` / `admin`; set `DASHBOARD_USER` and `DASHBOARD_PASSWORD` to override them.

The app initializes `users.db` automatically. The application and dashboard must run on the endpoint whose metrics you want to collect: the collector reads metrics from the machine running Flask.

## Train the anomaly model

The repository includes an `endpoint_data.csv` sample dataset and an `iso_forest.pkl` model. To train a new model, collect data first, then run the training script from the project directory:

```bash
python module1_collect.py
```

Stop collection with `Ctrl+C`, then train:

```bash
python module2_detect.py
```

The collector writes to `endpoint_data.csv`; training reads that file and saves the fitted model and scaler to `iso_forest.pkl`. Training and runtime paths are relative to the current working directory, so run commands from the project directory. Training overwrites the existing model file.

## Demonstration CPU load

To exercise the sustained-CPU correlation rules in a separate terminal, run:

```bash
python module5_attack.py
```

This script starts local CPU-intensive worker processes for a short, fixed duration. Use it only on a machine where you are authorized to run a load test. It is a demonstration, not an attack tool.

## Architecture

| Component | Responsibility |
| --- | --- |
| `app.py` | Flask routes, session checks, and orchestration of the metrics pipeline. |
| `auth_users.py` | SQLite user registration and password hash verification. |
| `module1_collect.py` | Collects live endpoint metrics; can also write samples to CSV when run directly. |
| `module2_detect.py` | Trains the Isolation Forest and scores new metric samples. |
| `module3_correlate.py` | Applies rule-based metric checks labeled with ATT&CK techniques. |
| `module4_alert.py` | Creates alerts and summarizes their severity counts in memory. |
| `module5_attack.py` | Runs the controlled CPU-load demonstration. |
| `templates/` | Login, registration, and monitoring dashboard pages. |

The dashboard requests `/api/metrics` every five seconds. That endpoint collects a fresh sample, scores it, runs correlation rules, generates an alert if a rule matched, and returns the results as JSON. Both the dashboard and API require a logged-in session.

## API

### `GET /api/metrics`

Requires an authenticated session. A successful response contains:

- `metrics`: latest endpoint sample.
- `anomaly`: Isolation Forest anomaly result, score, and raw outlier result.
- `correlations`: matched heuristic ATT&CK-labeled rules.
- `alert`: highest-priority generated alert, or `null` when no rule matched.
- `summary`: in-memory counts of alerts by severity.

Unauthenticated API requests receive HTTP `401`.

## Important limitations and security notes

- **Development server:** `app.py` currently starts Flask with debug mode enabled. Do not expose this development server to the internet or use it for production deployment.
- **Default credentials:** the fallback login defaults to `admin` / `admin` unless overridden with `DASHBOARD_USER` and `DASHBOARD_PASSWORD`. Change these values and use a strong `FLASK_SECRET_KEY`; never deploy with defaults.
- **Open registration:** anyone who can reach the app can register an account. There is no administrator approval or registration restriction in the current implementation.
- **Prototype authentication:** the app does not currently implement CSRF protection or login rate limiting.
- **Heuristic detection:** ATT&CK labels come from simple CPU/process-count rules; they do not establish that a technique occurred. Some rules are intentionally disabled.
- **Training data:** network and disk features are cumulative byte counters. Their values increase over time, which can cause drift and unreliable anomaly scores. Use representative data and interpret model results cautiously.
- **Alert storage:** alert history and severity summaries are held in process memory. They are lost when the process restarts and are not shared across multiple server workers.
- **Optional model:** if `iso_forest.pkl` is missing, the application reports no ML anomaly; correlation rules can still run. The model file must be trusted because loading a serialized joblib model can execute code.

## Project files

```text
app.py
auth_users.py
endpoint_data.csv
iso_forest.pkl
module1_collect.py
module2_detect.py
module3_correlate.py
module4_alert.py
module5_attack.py
requirements.txt
templates/
```
