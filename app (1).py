import os
import sys
import json
import time
import hashlib
import logging
import re
import shutil
import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("KBPipeline")

# ------------------------------------------------------------------------------
# 1. SECURITY & ACCESS CONTROL
# ------------------------------------------------------------------------------

class SecurityModule:
    def __init__(self):
        self.roles = {
            "admin": ["read", "write", "approve", "rollback", "admin"],
            "operator": ["read", "write", "approve"],
            "viewer": ["read"]
        }
        # Common prompt injection patterns
        self.injection_patterns = [
            r"ignore previous instructions",
            r"disregard all prior directives",
            r"system prompt override",
            r"you are now DAN",
            r"jailbreak"
        ]

    def authorize(self, user_role: str, required_permission: str) -> bool:
        permissions = self.roles.get(user_role, [])
        if required_permission not in permissions:
            logger.warning(f"Unauthorized access attempt by role: {user_role} for perm: {required_permission}")
            return False
        return True

    def sanitize_input(self, text: str) -> str:
        """Detect prompt injection attacks."""
        for pattern in self.injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                logger.error(f"Prompt injection pattern detected: '{pattern}'")
                raise ValueError("Potential prompt injection attack detected.")
        return text

    def mask_pii(self, text: str) -> str:
        """Mask sensitive data like emails, phone numbers, and SSNs."""
        # Email masking
        text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[REDACTED_EMAIL]', text)
        # Phone masking (general 10-digit / international patterns)
        text = re.sub(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b', '[REDACTED_PHONE]', text)
        # SSN / Sensitive ID masking
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED_SSN]', text)
        return text


# ------------------------------------------------------------------------------
# 2. MONITORING & TELEMETRY
# ------------------------------------------------------------------------------

@dataclass
class TelemetryMetrics:
    latency_ms: List[float] = field(default_factory=list)
    failure_count: int = 0
    total_requests: int = 0
    confidence_scores: List[float] = field(default_factory=list)
    escalations: int = 0

    def record_request(self, latency: float, success: bool, confidence: float, escalated: bool = False):
        self.total_requests += 1
        self.latency_ms.append(latency)
        self.confidence_scores.append(confidence)
        if not success:
            self.failure_count += 1
        if escalated:
            self.escalations += 1

    def get_summary(self) -> Dict[str, Any]:
        avg_latency = sum(self.latency_ms) / len(self.latency_ms) if self.latency_ms else 0.0
        avg_conf = sum(self.confidence_scores) / len(self.confidence_scores) if self.confidence_scores else 0.0
        error_rate = (self.failure_count / self.total_requests) if self.total_requests > 0 else 0.0
        escalation_rate = (self.escalations / self.total_requests) if self.total_requests > 0 else 0.0

        return {
            "total_requests": self.total_requests,
            "avg_latency_ms": round(avg_latency, 2),
            "error_rate": round(error_rate, 4),
            "avg_confidence": round(avg_conf, 4),
            "escalation_rate": round(escalation_rate, 4)
        }


# ------------------------------------------------------------------------------
# 3. KNOWLEDGE BASE STORAGE & VERSIONING
# ------------------------------------------------------------------------------

class KBStorageEngine:
    def __init__(self, base_dir: str = "./kb_system"):
        self.base_dir = base_dir
        self.data_dir = os.path.join(base_dir, "active_kb")
        self.versions_dir = os.path.join(base_dir, "versions")
        self.quarantine_dir = os.path.join(base_dir, "quarantine")
        self.staging_dir = os.path.join(base_dir, "staging")
        self._init_dirs()

    def _init_dirs(self):
        for d in [self.data_dir, self.versions_dir, self.quarantine_dir, self.staging_dir]:
            os.makedirs(d, exist_ok=True)

    def get_active_files(self) -> List[str]:
        return [os.path.join(self.data_dir, f) for f in os.listdir(self.data_dir) if f.endswith(".json")]

    def quarantine_file(self, file_path: str, reason: str):
        filename = os.path.basename(file_path)
        dest = os.path.join(self.quarantine_dir, f"{filename}.quarantined")
        shutil.copy(file_path, dest)
        logger.warning(f"File '{filename}' quarantined. Reason: {reason}")

    def create_version(self, version_id: str, documents: List[Dict[str, Any]]):
        v_path = os.path.join(self.versions_dir, f"version_{version_id}.json")
        with open(v_path, "w") as f:
            json.dump(documents, f, indent=2)
        logger.info(f"Version {version_id} stored with {len(documents)} documents.")

    def rollback_to_version(self, version_id: str):
        v_path = os.path.join(self.versions_dir, f"version_{version_id}.json")
        if not os.path.exists(v_path):
            raise FileNotFoundError(f"Version file {v_path} does not exist.")

        # Clear current active KB
        for f in os.listdir(self.data_dir):
            os.remove(os.path.join(self.data_dir, f))

        # Restore version
        with open(v_path, "r") as f:
            docs = json.load(f)

        for i, doc in enumerate(docs):
            doc_path = os.path.join(self.data_dir, f"doc_{i}.json")
            with open(doc_path, "w") as df:
                json.dump(doc, df, indent=2)

        logger.info(f"Successfully rolled back active KB to version {version_id}")


# ------------------------------------------------------------------------------
# 4. EVALUATION & QUALITY GATES
# ------------------------------------------------------------------------------

class QualityGate:
    """Evaluates proposed KB updates for Accuracy and Grounding drops."""
    def __init__(self, min_accuracy: float = 0.85, min_grounding: float = 0.90):
        self.min_accuracy = min_accuracy
        self.min_grounding = min_grounding

    def evaluate_candidate_kb(self, candidate_docs: List[Dict[str, Any]], baseline_accuracy: float) -> Tuple[bool, Dict[str, float]]:
        # Test benchmark queries against candidate KB
        # Synthetic quality metrics computation
        valid_docs = [d for d in candidate_docs if len(d.get("content", "")) > 10]
        grounding_score = len(valid_docs) / len(candidate_docs) if candidate_docs else 0.0

        # Accuracy mock score based on document structure integrity
        accuracy_score = 0.92 if grounding_score >= 0.8 else 0.70

        metrics = {
            "accuracy": round(accuracy_score, 4),
            "grounding": round(grounding_score, 4),
            "baseline_accuracy": baseline_accuracy
        }

        # Quality Gate condition: Must meet thresholds and NOT degrade baseline accuracy
        passed = (
            accuracy_score >= self.min_accuracy and
            grounding_score >= self.min_grounding and
            accuracy_score >= baseline_accuracy
        )

        return passed, metrics


# ------------------------------------------------------------------------------
# 5. INGESTION, DEDUPLICATION & PIPELINE ENGINE
# ------------------------------------------------------------------------------

class KBPipelineEngine:
    def __init__(self, storage: KBStorageEngine, security: SecurityModule, telemetry: TelemetryMetrics):
        self.storage = storage
        self.security = security
        self.telemetry = telemetry
        self.quality_gate = QualityGate()
        self.processed_hashes = set()
        self.current_version = "v1.0"
        self.baseline_accuracy = 0.88

    def _calculate_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    def process_incoming_directory(self, input_dir: str, user_role: str) -> Optional[str]:
        """Runs the incremental pipeline with deduplication, security, and quality gates.""" 
        start_time = time.time()

        if not self.security.authorize(user_role, "write"):
            raise PermissionError("User unauthorized to update Knowledge Base.")

        logger.info(f"Starting KB ingestion pipeline from '{input_dir}'...")
        new_candidate_docs = []
        raw_files = [os.path.join(input_dir, f) for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))]

        for file_path in raw_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # 1. Validation check
                if not content.strip() or len(content) < 5:
                    self.storage.quarantine_file(file_path, "Corrupted or empty file content.")
                    continue

                # 2. Prompt Injection Check
                self.security.sanitize_input(content)

                # 3. Sensitive Data Masking
                clean_content = self.security.mask_pii(content)

                # 4. Deduplication
                doc_hash = self._calculate_hash(clean_content)
                if doc_hash in self.processed_hashes:
                    logger.info(f"Duplicate document skipped: {os.path.basename(file_path)}")
                    continue

                self.processed_hashes.add(doc_hash)
                new_candidate_docs.append({
                    "id": doc_hash[:12],
                    "source": os.path.basename(file_path),
                    "content": clean_content,
                    "timestamp": datetime.datetime.utcnow().isoformat()
                })

            except Exception as e:
                self.storage.quarantine_file(file_path, str(e))
                latency = (time.time() - start_time) * 1000
                self.telemetry.record_request(
                    latency=latency,
                    success=False,
                    confidence=0.0
                )

        # Proceed with Quality Gate check on candidate documents
        if new_candidate_docs:
            passed, metrics = self.quality_gate.evaluate_candidate_kb(new_candidate_docs, self.baseline_accuracy)
            latency = (time.time() - start_time) * 1000
            self.telemetry.record_request(
                latency=latency,
                success=passed,
                confidence=metrics.get("accuracy", 0.0)
            )
            if passed:
                new_version = f"v{float(self.current_version[1:]) + 0.1:.1f}"
                self.storage.create_version(new_version, new_candidate_docs)
                self.current_version = new_version
                return new_version
            else:
                logger.warning("Quality gate failed. Ingestion aborted.")
        return None
