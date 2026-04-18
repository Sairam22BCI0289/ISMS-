# ISMS Project Context Report

Generated for sharing project context with another ChatGPT/Codex chat.

Workspace path:

```text
C:\Users\chini\Documents\isms
```

## 1. Project Summary

This project is a local ISMS/security-monitoring prototype with:

- A FastAPI backend.
- A SQLite event store.
- A browser dashboard served by the backend.
- Host, network, and AWS CloudTrail ingestion agents.
- Rule-based severity and reasoning.
- Multiple ML anomaly detectors:
  - Host authentication Isolation Forest.
  - Host behavior Isolation Forest.
  - Network Isolation Forest.
  - Network OCSVM.
  - Cloud autoencoder.
- Offline public-dataset conversion/training/evaluation scripts for host, network, and cloud ML.

The backend receives normalized events through `POST /events`, stores them in `security_events`, enriches them with rule severity/reasons, and scores them through `app.ml.anomaly_service.score_event(...)`.

## 2. Top-Level Folder Architecture

```text
isms/
  start_isms.bat
  stop_isms.bat
  data/
    cloud_logs/
      cloudtrail_like_20260101_135926.json
  backend/
    run_backend.bat
    run_host_agent.bat
    run_network_agent.bat
    run_cloud_agent.bat
    convert_evtx_to_json.ps1
    evtx_to_json.py
    isms.db
    app/
      main.py
      config.py
      schemas.py
      db/
        base.py
        models.py
        crud.py
      ingest/
        host_windows_eventlog.py
        network_windows_firewall.py
        cloud_aws_cloudtrail.py
        cloud_importer.py
        cloud_generator.py
      ml/
        anomaly_service.py
        features.py
        model_registry.py
        training/evaluation/dataset scripts
      ui/
        dashboard.html
    data/
      cloud_logs/
      host_logs/
      public_datasets/
    models/
      trained model artifacts
```

## 3. Runtime Launchers

The project launcher scripts currently use the Python 3.11 virtual environment:

```text
backend\.venv311
```

Important launchers:

- `start_isms.bat`
  - Starts the backend and agents.
  - Opens the dashboard URL.
  - Uses `backend\.venv311`.
- `backend/run_backend.bat`
  - Activates `.venv311`.
  - Runs:

```bat
python -m uvicorn app.main:app --port 8000
```

- `backend/run_host_agent.bat`
  - Runs:

```bat
python app\ingest\host_windows_eventlog.py
```

- `backend/run_network_agent.bat`
  - Runs:

```bat
python app\ingest\network_windows_firewall.py
```

- `backend/run_cloud_agent.bat`
  - Clears `SSLKEYLOGFILE`.
  - Runs:

```bat
python -m app.ingest.cloud_aws_cloudtrail
```

No dependency manifest such as `requirements.txt` or `pyproject.toml` was found outside the virtual environments.

## 4. Backend API Flow

Main file:

```text
backend/app/main.py
```

Important pieces:

- `EventIn`
  - Incoming event schema.
  - Allows extra fields.
  - Supports anomaly fields, rule fields, and raw payload.
- `EventOut`
  - Dashboard/API response shape.
  - Includes:
    - `anomaly_score`
    - `anomaly_score_svm`
    - `anomaly_risk_10`
    - `anomaly_risk_10_svm`
    - `host_auth_risk`
    - `host_behavior_risk`
    - `host_multilayer_risk`
    - `network_multilayer_risk`
    - `anomaly_label`
    - `anomaly_label_svm`
    - `anomaly_model`
    - `anomaly_source_profile`
    - `severity`
    - `severity_reason`
    - `rules_triggered`
    - `raw`
- `normalize_event(payload)`
  - Normalizes timestamp, source, event type, rules, and raw JSON.
  - Applies host future timestamp correction.
- `POST /events`
  - Calls `crud.create_event(db, data)`.
- `GET /events`
  - Returns latest events for dashboard.
- `GET /dashboard`
  - Serves `backend/app/ui/dashboard.html`.

## 5. Database Layer

Files:

```text
backend/app/db/base.py
backend/app/db/models.py
backend/app/db/crud.py
```

Database:

```text
backend/isms.db
```

Main model:

```python
class SecurityEvent(Base):
    __tablename__ = "security_events"
```

Stored fields include:

- `source`
- `event_type`
- `timestamp`
- `actor`
- `ip`
- `resource`
- `severity`
- `severity_reason`
- `rules_triggered`
- `raw`
- generic anomaly fields
- host component risk fields
- network multilayer risk field

`crud.create_event(...)` is the main persistence path. It:

1. Infers rule severity and reason if missing.
2. Applies host rule enrichment.
3. Serializes `rules_triggered` and `raw`.
4. Deduplicates host/cloud events where possible.
5. Calls `score_event(...)`.
6. Stores rule fields and anomaly fields.

Recent host rule enrichment in `crud.py` includes:

- `HOST_MULTIPLE_FAILED_LOGIN_ATTEMPTS`
  - 5 failed logins within 10 seconds for same actor and/or IP.
- `HOST_SUCCESSFUL_LOGIN_AFTER_MULTIPLE_FAILURES`
  - Login success after recent failed-login burst.
- `HOST_WHOAMI_EXECUTION`
  - Event 4688 with `whoami` in process/command text.
- `HOST_USB_INSERTED`
  - USB/external device insertion event.

Blocked rule:

- Outbound traffic over 25 MB is not implemented because current live network telemetry does not expose per-event byte counts.

## 6. Ingestion Agents

### Host: Windows Event Log

File:

```text
backend/app/ingest/host_windows_eventlog.py
```

Purpose:

- Reads Windows Event Log through pywin32.
- Posts normalized host events to `/events`.
- Preserves enriched raw host telemetry for ML/rules.

Channels:

```text
Security
System
Microsoft-Windows-Sysmon/Operational
Microsoft-Windows-DriverFrameworks-UserMode/Operational
```

Important event IDs:

- Auth:
  - `4624` -> `win_login_success`
  - `4625` -> `win_login_failed`
  - `4648` -> `win_event_4648`
  - `4672` -> `win_event_4672`
- Behavior:
  - `4688`
  - `4656`
  - `4663`
  - `10`
  - `5156`
- USB/device:
  - `6416`
  - `20001`
  - `20003`
  - `2100`

Host raw payload preserves:

- `channel`
- `source`
- `event_id`
- `record_number`
- `event_category`
- `source_ip`
- `logon_type`
- `process_name`
- `string_inserts`
- `computer_name`

Startup/backlog behavior:

- Uses `backend/data/host_logs/host_event_state.json`.
- Has startup cutoff logic so stale pre-startup Windows events are skipped while record watermarks advance.
- This avoids replaying old Windows logs on startup.

### Network: Windows TCP Connections

File:

```text
backend/app/ingest/network_windows_firewall.py
```

Purpose:

- Uses `psutil.net_connections(kind="tcp")`.
- Emits live connection/listener events.
- Posts to `/events`.

Event types:

- `net_listener_open`
- `net_conn_high_risk`
- `net_conn_allowed`

Raw network fields include:

- `status`
- `pid`
- `process_name`
- `local_ip`
- `local_port`
- `remote_ip`
- `remote_port`
- `high_risk_port`

Limitation:

- This source does not provide per-event outbound byte counts, so data-exfiltration volume rules cannot be safely implemented from it.

### Cloud: AWS CloudTrail

File:

```text
backend/app/ingest/cloud_aws_cloudtrail.py
```

Purpose:

- Uses `boto3` CloudTrail `lookup_events`.
- Converts events into normalized ISMS cloud events.
- Posts to `/events`.

Important helper functions:

- `map_event_type(event_name, cloudtrail_event)`
- `extract_actor(cloudtrail_event, wrapper_event)`
- `extract_resource(wrapper_event, cloudtrail_event, event_name)`
- `rules_for_event_type(event_type, event_name, cloudtrail_event)`
- `parse_cloudtrail_event(wrapper_event)`

Cloud event types include:

- `cloud_auth_success`
- `cloud_auth_failed`
- `cloud_iam_change`
- `cloud_policy_change`
- `cloud_role_assumption`
- `cloud_network_change`
- `cloud_key_management`
- `cloud_storage_access`
- `cloud_audit_activity`
- `cloud_service_activity`
- `cloud_identity_activity`
- `cloud_compute_activity`
- `cloud_resource_create`
- `cloud_resource_delete`
- `cloud_other`

Cloud raw payload preserves:

- `EventId`
- `EventName`
- `EventTime`
- `Username`
- `CloudTrailEvent`
- `Resources`

## 7. Rule-Based Severity

Primary file:

```text
backend/app/db/crud.py
```

Rules are represented through:

- `severity`
- `severity_reason`
- `rules_triggered`

Cloud severity examples:

- High:
  - `cloud_policy_change`
  - `cloud_key_management`
  - `cloud_network_change`
- Medium:
  - `cloud_auth_failed`
  - `cloud_role_assumption`
  - `cloud_resource_delete`
  - `cloud_identity_activity`
  - `cloud_audit_activity`
- Low:
  - routine cloud activity and default cases.

Host severity examples:

- High:
  - `win_login_failed`
  - multiple failed login burst
  - success after failed burst
- Medium:
  - `win_event_4672`
  - `win_event_4648`
  - `HOST_WHOAMI_EXECUTION`
  - `HOST_USB_INSERTED`
- Low:
  - login success and routine/default host events.

Network severity examples:

- High:
  - `net_conn_high_risk`
- Medium:
  - `net_listener_open`
- Low:
  - allowed/blocked/default network events.

## 8. ML Architecture

Primary files:

```text
backend/app/ml/features.py
backend/app/ml/model_registry.py
backend/app/ml/anomaly_service.py
```

### Feature Extraction

`features.py` exposes:

- `extract_network_features(event)`
- `extract_cloud_features(event)`
- `extract_host_features(event)`
- `extract_host_behavior_features(event, stats=None)`

Cloud feature vector:

- 18 fixed numeric features from normalized CloudTrail fields.
- Uses:
  - `event_type`
  - `eventName`
  - `eventSource`
  - `actor`
  - `resource`
  - `userAgent`
  - hour/off-hours
  - public IP flag
  - errorCode flag
  - userIdentity.type flags
  - AssumeRole/read/write/delete action flags

Host auth feature vector:

- 21 fixed numeric features including:
  - event_id
  - event_type hash
  - actor hash/presence
  - hour
  - channel/provider
  - privileged flag
  - auth outcome
  - frequencies
  - off-hours
  - source IP
  - logon type
  - process/computer fields

Host behavior feature vector:

- Fixed behavior features for event IDs:

```python
BEHAVIOR_EVENT_IDS = {4688, 4656, 4663, 10, 5156}
```

Includes process, LOLBIN, LSASS/SAM/registry/startup targets, port/protocol buckets, and frequency-style values.

### Model Registry

`model_registry.py` loads/caches artifacts from:

```text
backend/models/
```

Important live model artifacts:

- Host auth:
  - `host_isolation_forest.joblib`
  - `host_isolation_forest_meta.json`
- Host behavior:
  - `host_behavior_iforest.joblib`
  - `host_behavior_iforest_meta.json`
- Network IF:
  - `network_isolation_forest.joblib`
  - `network_isolation_forest_meta.json`
- Network OCSVM:
  - `network_ocsvm.joblib`
  - `network_ocsvm_scaler.joblib`
  - `network_ocsvm_meta.json`
- Cloud autoencoder:
  - `cloud_autoencoder.keras`
  - `cloud_autoencoder_scaler.joblib`
  - `cloud_autoencoder_meta.json`

Alternate comparison model artifacts:

- `cloud_autoencoder_hybrid.keras`
- `cloud_autoencoder_hybrid_scaler.joblib`
- `cloud_autoencoder_hybrid_meta.json`

### Runtime Scoring

`anomaly_service.py` exposes:

```python
score_event(event: dict) -> dict
```

Routing:

- `source == "host"`
  - Auth event IDs use `iforest_host_auth_v1`.
  - Behavior event IDs use `iforest_host_behavior_v1`.
  - Host auth/behavior scores are fused over a 5-minute host context window.
- `source == "network"`
  - Uses network IF and OCSVM if available.
  - Produces `network_multilayer_risk`.
- `source == "cloud"`
  - Uses cloud autoencoder reconstruction error.
  - Produces:
    - `anomaly_score`
    - `anomaly_risk_10`
    - `anomaly_label`
    - `anomaly_model`
    - `anomaly_source_profile`

Cloud noise suppression:

- Keeps real reconstruction error.
- Downgrades two known benign patterns to normal/low risk:
  - CloudTrail `LookupEvents` by IAMUser/Boto3/Botocore.
  - AWSService `AssumeRole` on `sts.amazonaws.com`.

## 9. Dashboard

File:

```text
backend/app/ui/dashboard.html
```

Purpose:

- Browser UI served from `GET /dashboard`.
- Polls `GET /events`.
- Displays event source, severity, rule reason, anomaly label/risk, and raw payload.
- Details modal includes:
  - Event meaning.
  - Rule-based severity.
  - ML analysis.
  - Triggered rules.
  - Recommended actions.
  - Raw JSON.

Dashboard-specific logic includes:

- Host ML explanation:
  - host auth risk
  - host behavior risk
  - host multilayer risk
  - host fusion weighting
- Network ML explanation:
  - IF risk
  - OCSVM score/risk
  - network multilayer risk
- Cloud ML explanation:
  - model name
  - reconstruction error
  - cloud anomaly risk
  - label
  - CloudTrail event/source context

## 10. Offline Dataset And Training Scripts

Important ML/data scripts in `backend/app/ml/`:

### Network

- `convert_cicids_to_isms.py`
  - Converts CICIDS-style flow data into ISMS JSONL.
- `train_network_iforest.py`
- `train_network_iforest_cicids.py`
- `train_network_ocsvm.py`
- `train_network_ocsvm_cicids.py`
- `evaluate_iforest_threshold.py`
- `evaluate_ocsvm_threshold.py`
- `validate_iforest_cicids.py`
- `validate_ocsvm_cicids.py`

### Host

- `build_public_host_dataset.py`
  - Builds curated auth-only public host dataset.
  - Uses raw Mordor and converted EVTX JSON sources.
  - Outputs:
    - `train_host_public.jsonl`
    - `val_host_public.jsonl`
- `build_external_host_dataset.py`
- `export_host_dataset.py`
- `train_host_iforest.py`
- `validate_host_iforest.py`
- `evaluate_host_iforest_threshold.py`
- `train_host_behavior_iforest.py`

### Cloud

- `build_public_cloud_dataset.py`
  - Converts public Invictus AWS CloudTrail data into normalized ISMS JSONL.
  - Input:
    - `backend/data/public_datasets/cloud_public/invictus_aws_dataset/CloudTrail`
  - Output:
    - `backend/data/public_datasets/cloud_public/public_cloud_normalized.jsonl`
- `train_cloud_autoencoder.py`
  - Trains live local cloud autoencoder from DB rows.
  - Excludes local benign noise during training.
  - Saves live artifacts:
    - `cloud_autoencoder.keras`
    - `cloud_autoencoder_scaler.joblib`
    - `cloud_autoencoder_meta.json`
- `train_cloud_autoencoder_hybrid.py`
  - Trains comparison cloud model from DB + public normalized cloud data.
  - Saves alternate artifacts only.
- `evaluate_cloud_live_model.py`
  - Evaluates current live cloud scorer via `score_event(...)`.
  - Input:
    - `cloud_eval_labeled.jsonl`

## 11. Public Dataset/Data Paths

Main public dataset directory:

```text
backend/data/public_datasets/
```

Network:

```text
backend/data/public_datasets/cicids2017/
  MachineLearningCSV.zip
  MachineLearningCSV/MachineLearningCVE/*.csv
  cicids2017_isms_network.jsonl
  train_sample.jsonl
  val_sample.jsonl
```

Host:

```text
backend/data/public_datasets/host_public_raw/
  mordor/
  evtx_tmp/
  evtx_attack_samples/

backend/data/public_datasets/host_public/
  train_host_public.jsonl
  val_host_public.jsonl

backend/data/public_datasets/host_external/
  train_host_external.jsonl
  val_host_external.jsonl

backend/data/public_datasets/host_local/
  train_host.jsonl
  val_host.jsonl
```

Cloud:

```text
backend/data/public_datasets/cloud_public/
  invictus_aws_dataset/
    CloudTrail/
  public_cloud_normalized.jsonl
  cloud_eval_labeled.jsonl
```

State files:

```text
backend/data/cloud_logs/cloudtrail_state.json
backend/data/host_logs/host_event_state.json
```

## 12. EVTX Conversion Utilities

Files:

```text
backend/convert_evtx_to_json.ps1
backend/evtx_to_json.py
```

Purpose:

- Convert raw `.evtx` files from:

```text
backend/data/public_datasets/host_public_raw/evtx_tmp
```

- Into JSON/JSONL under:

```text
backend/data/public_datasets/host_public_raw/evtx_attack_samples
```

`evtx_to_json.py` uses `python-evtx` if available and writes JSON objects per EVTX record.

## 13. Current Git/Workspace Notes

At the time this report was generated, the working tree included saved but not necessarily committed changes. Notable modified or new paths included:

- Modified:
  - `backend/app/db/crud.py`
  - `backend/app/ingest/host_windows_eventlog.py`
  - `backend/app/ml/anomaly_service.py`
  - `backend/app/ml/features.py`
  - `backend/app/ml/model_registry.py`
  - `backend/app/ui/dashboard.html`
  - launcher `.bat` files
- New:
  - `backend/app/ml/build_public_cloud_dataset.py`
  - `backend/app/ml/evaluate_cloud_live_model.py`
  - `backend/app/ml/train_cloud_autoencoder.py`
  - `backend/app/ml/train_cloud_autoencoder_hybrid.py`
  - cloud autoencoder artifacts under `backend/models/`
  - `backend/.venv311/`

Use this command to check the current status:

```powershell
git status --short
```

## 14. Important Recent Behavior/Design Decisions

- Host runtime ML has two profiles:
  - `host_auth`
  - `host_behavior`
- Host multilayer risk fuses auth and behavior risk over a 5-minute context window.
- Cloud runtime ML uses the live local cloud autoencoder, not the hybrid comparison model.
- Cloud noise suppression is post-ML:
  - reconstruction error remains real.
  - final label/risk/model are adjusted for known benign noise.
- Host Windows Event Log ingestion has a startup cutoff to avoid replaying stale old logs.
- USB support is best-effort and depends on Windows channel/audit availability.
- Network exfiltration by outbound byte threshold is blocked until real byte-volume telemetry exists.

## 15. Useful Commands

Run backend from `backend/`:

```powershell
.\.venv311\Scripts\python.exe -m uvicorn app.main:app --port 8000
```

Run host agent from repo root:

```powershell
backend\.venv311\Scripts\python.exe backend\app\ingest\host_windows_eventlog.py
```

Run cloud public dataset builder from `backend/`:

```powershell
.\.venv311\Scripts\python.exe -m app.ml.build_public_cloud_dataset
```

Run cloud live evaluator from `backend/`:

```powershell
.\.venv311\Scripts\python.exe -m app.ml.evaluate_cloud_live_model
```

Syntax-check key Python files:

```powershell
backend\.venv311\Scripts\python.exe -B -m py_compile backend\app\main.py backend\app\db\crud.py backend\app\ml\anomaly_service.py backend\app\ml\features.py backend\app\ml\model_registry.py
```

Dashboard URL:

```text
http://127.0.0.1:8000/dashboard
```

## 16. Context To Give Another ChatGPT Chat

When asking another ChatGPT/Codex chat for help, include:

1. The workspace path: `C:\Users\chini\Documents\isms`.
2. This report.
3. The specific files relevant to the task.
4. The current `git status --short`.
5. A reminder not to alter host/network/cloud ML behavior unless requested.
6. A reminder that `.venv311` is the active environment.
7. If touching data/model code, mention that public datasets live under `backend/data/public_datasets/` and models under `backend/models/`.

