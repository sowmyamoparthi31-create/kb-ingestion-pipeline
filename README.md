%%writefile README.md
# Production Knowledge Base Pipeline for Chatbots

A production-grade, automated Knowledge Base (KB) ingestion, monitoring, security, and lifecycle management engine designed for Retrieval-Augmented Generation (RAG) chatbots.

---

## Key Features

* **Incremental Ingestion & Deduplication**: Processes only new or modified documents using SHA-256 hashing to eliminate duplicates.
* **Validation & Quarantine**: Automatically detects empty or corrupt files and moves them to an isolated quarantine directory.
* **Security & Compliance**:
  * **Role-Based Access Control (RBAC)**: Role checks (`admin`, `operator`, `viewer`) for write and activation permissions.
  * **Prompt Injection Defense**: Regex-based sanitization for common jailbreak and prompt override patterns.
  * **PII Masking**: Redacts sensitive data including emails, phone numbers, and Social Security Numbers (SSNs).
* **Quality Gate & Automated Evaluation**: Benchmarks candidate updates against baseline metrics (grounding score and accuracy) before allowing deployment.
* **Resilient Scheduling & Backoff**: Retries failed ingestion jobs with exponential backoff intervals (15, 30, 60 minutes).
* **Safe Maintenance Window Activations**: Enforces update activations strictly within maintenance windows.
* **Automated Rollback Watchdog**: Performs post-activation health checks and automatically rolls back if metrics degrade.
* **Telemetry & Operational Metrics**: Tracks latency, error rate, average confidence, and escalation rates.

---

## Directory Structure

```text
.
├── app.py                  # Main execution pipeline script
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation
└── kb_system/              # KB storage root
    ├── active_kb/          # Currently deployed KB documents
    ├── incoming/           # Input directory for raw documents
    ├── quarantine/         # Isolated invalid/corrupted documents
    ├── staging/            # Temporary holding during evaluation
    └── versions/           # Version snapshots (JSON format)
