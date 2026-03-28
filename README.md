# 🌱 Agri AI Security Copilot

> **Self-Healing Industrial IoT Security System for Smart Agriculture**

An AI-powered, multi-agent security platform that protects farm IoT devices by detecting cyber threats and sensor anomalies in real time, automatically remediating incidents, and providing RAG-based fix recommendations — all integrated with an n8n automation workflow.

---

## ✨ Features

| Feature | Description |
|---|---|
| **Multi-Agent AI** | Specialised agents for anomaly detection, threat detection, self-healing, and advisory |
| **Anomaly Detection** | Threshold, statistical (z-score), and isolation-forest methods for sensor readings |
| **Cyber Threat Detection** | Port scanning, brute-force, MITM, DDoS, firmware tampering, replay attacks, command injection |
| **Automated Self-Healing** | Builds and executes remediation plans (block IPs, quarantine devices, rotate credentials, etc.) |
| **RAG-Based Advisories** | TF-IDF retrieval over a built-in IoT security knowledge base returns context-aware fix guidance |
| **Predictive Maintenance** | Linear-regression trend analysis on battery, RSSI, error rate, and calibration drift |
| **n8n Integration** | Ready-to-import workflow JSON connecting IoT webhooks → detection → healing → Slack/DB |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 MultiAgentOrchestrator                      │
│                                                             │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────────┐  │
│  │SensorAgent │  │ThreatAgent │  │  MaintenanceAgent    │  │
│  │(Anomaly    │  │(Cyber      │  │  (Predictive         │  │
│  │ Detector)  │  │ Threats)   │  │   Maintenance)       │  │
│  └─────┬──────┘  └─────┬──────┘  └──────────┬───────────┘  │
│        │               │                    │               │
│        └───────┬────────┘                   │               │
│                ▼                            │               │
│        ┌───────────────┐                   │               │
│        │  HealingAgent │◄──────────────────┘               │
│        │ (Self-Healer) │                                    │
│        └───────┬───────┘                                    │
│                │                                            │
│                ▼                                            │
│        ┌───────────────┐                                    │
│        │  Advisory     │                                    │
│        │  Agent (RAG)  │                                    │
│        └───────────────┘                                    │
└─────────────────────────────────────────────────────────────┘
         ▲                    ▲
    IoT Sensors          Network Events
   (MQTT/CoAP/HTTP)     (Gateway IDS)
```

### Components

```
agri_security/
├── anomaly_detector.py      # Multi-method IoT sensor anomaly detection
├── threat_detector.py       # Cyber attack detection (7 threat types)
├── self_healer.py           # Automated remediation engine
├── rag_advisor.py           # TF-IDF RAG over 10-doc knowledge base
├── predictive_maintenance.py# Linear-regression device health forecasting
└── multi_agent.py           # Central orchestrator

config/
└── config.yaml              # Tunable parameters for every sub-system

data/
├── sample_sensor_readings.json   # Example IoT sensor data
└── sample_network_events.json    # Example network events

n8n/
└── agri_security_workflow.json   # Importable n8n workflow

tests/                       # 92 pytest tests (100% pass)
main.py                      # CLI entry point / n8n integration bridge
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- No mandatory third-party packages (standard library only for core functionality)

### Installation

```bash
git clone https://github.com/supunabeywickrama/agri-ai-security-copilot.git
cd agri-ai-security-copilot
pip install -r requirements.txt   # installs pytest only; core has no deps
```

### Run the demo

```bash
python main.py --mode demo
```

This processes the bundled sample sensor readings, network events, and predictive maintenance snapshots, printing a full incident report.

---

## 📡 CLI Usage

```bash
# Full end-to-end demo
python main.py --mode demo

# Analyse a single sensor reading (returns JSON)
python main.py --mode sensor --data '{"sensor_id":"S-TEMP-001","sensor_type":"temperature","value":85,"unit":"C","timestamp":"2024-01-15T08:00:00Z","device_id":"D-FIELD-01","location":"Field-A"}'

# Analyse a network event
python main.py --mode threat --data '{"event_id":"EVT-001","source_ip":"10.0.0.99","destination_ip":"10.0.0.1","destination_port":22,"protocol":"tcp","payload_size":64,"timestamp":"2024-01-15T09:00:00Z","device_id":"D-GW-01","auth_success":false}'

# Record a device health snapshot
python main.py --mode health --data '{"device_id":"D-FIELD-01","timestamp":"2024-01-15T08:00:00Z","battery_pct":18.0,"rssi_dbm":-88.0,"error_rate":3.0}'

# Approve pending manual healing steps
python main.py --mode heal --incident-id <uuid>

# Get RAG advice for an incident
python main.py --mode advise --incident-id <uuid>
```

---

## 🔌 n8n Integration

1. Open your n8n instance.
2. Go to **Settings → Import Workflow**.
3. Upload `n8n/agri_security_workflow.json`.
4. Configure credentials for Slack and PostgreSQL nodes.
5. Set the webhook endpoints on your IoT gateway to POST to:
   - `/webhook/iot-sensor-event` — sensor readings
   - `/webhook/network-event` — gateway IDS events
   - `/webhook/device-health` — periodic health snapshots

The workflow automatically routes events through Python detection scripts, evaluates results, triggers self-healing, fetches RAG advice, notifies Slack, and persists incidents to PostgreSQL.

---

## 🤖 Agent Details

### 1. Anomaly Detector

Detects abnormal sensor readings using three complementary methods:

| Method | Description |
|---|---|
| **Threshold** | Instant flag when a reading is outside the configured safe / warning range |
| **Statistical (Z-Score)** | Rolling-window mean/stdev; flags readings > 3σ from baseline |
| **Isolation Forest (IQR)** | Flags readings > 3× IQR from the rolling median |

Supported sensor types: `temperature`, `humidity`, `soil_moisture`, `ph`, `co2`, `light`, `wind_speed`, `battery`, `signal_strength`.

### 2. Threat Detector

Detects the following attack patterns:

| Threat | Detection Method |
|---|---|
| Port Scan | Tracks distinct destination ports per source IP |
| Brute Force | Counts consecutive auth failures per source IP |
| DDoS | Tracks packet rate in a sliding window |
| MITM | Detects unexpected gateway/source IP changes per device |
| Firmware Tamper | SHA-256 checksum comparison against registered baseline |
| Replay Attack | Deduplicates event IDs in a rolling cache |
| Command Injection | Regex-based detection of shell metacharacters, path traversal, and SQLi in payloads |

### 3. Self-Healer

Maps incident types to ordered remediation plans and executes them:

- **AUTO** actions execute immediately (block IP, alert operator, recalibrate sensor, etc.)
- **MANUAL** actions for critical/high severity require operator approval before execution

### 4. RAG Advisor

Retrieves the most relevant guidance from a 10-document knowledge base using TF-IDF cosine similarity.  Topics include MQTT hardening, firmware security, network segmentation, brute-force mitigation, MITM defence, command injection prevention, predictive maintenance, and Zero Trust.

### 5. Predictive Maintenance

Tracks per-device rolling histories of battery %, RSSI, error rate, uptime, and calibration drift. Uses linear regression to predict days-until-critical and assigns urgency levels: `ok → monitor → schedule → urgent → critical`.

---

## 🧪 Tests

```bash
python -m pytest tests/ -v
```

92 tests covering all five modules and the orchestrator — all passing.

```
tests/test_anomaly_detector.py       18 tests
tests/test_threat_detector.py        20 tests
tests/test_self_healer.py            13 tests
tests/test_rag_advisor.py            11 tests
tests/test_predictive_maintenance.py 13 tests
tests/test_multi_agent.py            17 tests
```

---

## ⚙️ Configuration

All thresholds, windows, and feature flags are tunable in `config/config.yaml`:

```yaml
anomaly_detection:
  zscore_threshold: 3.0
  thresholds:
    temperature: { min: -10, max: 60, warn_min: 0, warn_max: 50 }

threat_detection:
  port_scan_threshold: 15
  brute_force_threshold: 5

self_healing:
  auto_execute_max_severity: "high"  # critical incidents require manual approval
```

---

## 🔒 Security Notes

- No credentials are hard-coded; API keys/passwords must be supplied via environment variables.
- All incoming MQTT/CoAP payloads are validated against an injection-pattern allowlist before processing.
- Critical healing actions (firmware rollback, device quarantine) require explicit operator approval.
- The system logs all healing actions to an audit trail.

---

## 📜 License

MIT — see `LICENSE` for details.