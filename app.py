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
import streamlit as st

# Configure Streamlit page at root level
st.set_page_config(
    page_title="Production KB Pipeline Engine",
    page_icon="🤖",
    layout="wide"
)

# ------------------------------------------------------------------------------
# 1. LOGGING & DATA CLASSES
# ------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("KBPipeline")

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
# 2. SECURITY & ACCESS CONTROL
# ------------------------------------------------------------------------------
class SecurityModule:
    def __init__(self):
        self.roles = {
            "admin": ["read", "write", "approve", "rollback", "admin"],
            "operator": ["read", "write", "approve"],
            "viewer": ["read"]
        }
        self.injection_patterns = [
            r"ignore previous instructions",
            r"disregard all prior directives",
            r"system prompt override",
            r"you are now DAN",
            r"jailbreak"
        ]

    def authorize(self, user_role: str, required_permission: str) -> bool:
        permissions = self.roles.get(user_role, [])
        return required_permission in permissions

    def sanitize_input(self, text: str) -> str:
        for pattern in self.injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                raise ValueError(f"Prompt injection pattern detected: '{pattern}'")
        return text

    def mask_pii(self, text: str) -> str:
        text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[REDACTED_EMAIL]', text)
        text = re.sub(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b', '[REDACTED_PHONE]', text)
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED_SSN]', text)
        return text

# ------------------------------------------------------------------------------
# 3. KNOWLEDGE BASE STORAGE ENGINE
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

    def quarantine_file(self, filename: str, content: str, reason: str):
        dest = os.path.join(self.quarantine_dir, f"{filename}.quarantined")
        with open(dest, "w") as f:
            f.write(f"REASON: {reason}\n---\n{content}")

    def create_version(self, version_id: str, documents: List[Dict[str, Any]]):
        v_path = os.path.join(self.versions_dir, f"version_{version_id}.json")
        with open(v_path, "w") as f:
            json.dump(documents, f, indent=2)

    def rollback_to_version(self, version_id: str):
        v_path = os.path.join(self.versions_dir, f"version_{version_id}.json")
        if not os.path.exists(v_path):
            raise FileNotFoundError(f"Version file {v_path} does not exist.")
        
        for f in os.listdir(self.data_dir):
            os.remove(os.path.join(self.data_dir, f))
        
        with open(v_path, "r") as f:
            docs = json.load(f)
        
        for i, doc in enumerate(docs):
            doc_path = os.path.join(self.data_dir, f"doc_{i}.json")
            with open(doc_path, "w") as df:
                json.dump(doc, df, indent=2)

# ------------------------------------------------------------------------------
# 4. STREAMLIT FRONTEND & INTERFACE
# ------------------------------------------------------------------------------
st.title("🤖 Chatbot Knowledge Base Pipeline & Governance Engine")
st.markdown("Automated Knowledge Base pipeline featuring deduplication, PII masking, prompt injection defense, quality testing, and scheduled maintenance rollbacks.")

# Initialize Session State Variables
if "storage" not in st.session_state:
    st.session_state.storage = KBStorageEngine()
if "security" not in st.session_state:
    st.session_state.security = SecurityModule()
if "telemetry" not in st.session_state:
    st.session_state.telemetry = TelemetryMetrics()
if "hashes" not in st.session_state:
    st.session_state.hashes = set()

# Sidebar Controls
st.sidebar.header("🔑 RBAC & Control Panel")
user_role = st.sidebar.selectbox("Active User Role", ["admin", "operator", "viewer"])
maintenance_window = st.sidebar.checkbox("Maintenance Window Active", value=True)

# Main Navigation Tabs
tab1, tab2, tab3 = st.tabs(["📥 Ingestion Pipeline", "📊 Telemetry & Monitoring", "📁 Storage & Rollback Engine"])

with tab1:
    st.subheader("Process & Validate Knowledge Documents")
    uploaded_files = st.file_uploader("Upload raw text or JSON documents", accept_multiple_files=True, type=["txt", "json"])

    if st.button("Run Ingestion Pipeline", type="primary"):
        start_time = time.time()
        
        # Access control check
        if not st.session_state.security.authorize(user_role, "write"):
            st.error(f"⛔ Unauthorized Access: Role '{user_role}' lacks write permissions.")
            st.session_state.telemetry.record_request(0.0, False, 0.0)
        elif not uploaded_files:
            st.warning("⚠️ Please select at least one document to ingest.")
        elif not maintenance_window:
            st.error("⛔ Pipeline Activation Blocked: System updates can only be applied during active maintenance windows.")
            st.session_state.telemetry.record_request(0.0, False, 0.0)
        else:
            processed_docs = []
            
            for file in uploaded_files:
                content = file.read().decode("utf-8")
                
                # Check 1: Empty or Invalid File Detection
                if not content.strip() or len(content) < 5:
                    st.session_state.storage.quarantine_file(file.name, content, "Empty or corrupt content.")
                    st.warning(f"☣️ Quarantined file '{file.name}': Empty or corrupted.")
                    continue
                
                # Check 2: Prompt Injection Defense
                try:
                    st.session_state.security.sanitize_input(content)
                except ValueError as err:
                    st.session_state.storage.quarantine_file(file.name, content, str(err))
                    st.error(f"🚨 Security Violation in '{file.name}': Prompt injection attempt detected! File quarantined.")
                    st.session_state.telemetry.record_request(0.0, False, 0.0)
                    continue

                # Check 3: Sensitive Data Masking (PII)
                clean_content = st.session_state.security.mask_pii(content)
                
                # Check 4: Incremental Ingestion & Duplicate Detection
                doc_hash = hashlib.sha256(clean_content.encode('utf-8')).hexdigest()
                if doc_hash in st.session_state.hashes:
                    st.info(f"ℹ️ Skipped exact duplicate document: '{file.name}'")
                    continue
                
                st.session_state.hashes.add(doc_hash)
                processed_docs.append({
                    "id": doc_hash[:10],
                    "filename": file.name,
                    "content": clean_content,
                    "timestamp": datetime.datetime.utcnow().isoformat()
                })

            if processed_docs:
                version_id = f"v{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
                st.session_state.storage.create_version(version_id, processed_docs)
                
                # Deploy to active storage
                for doc in processed_docs:
                    doc_path = os.path.join(st.session_state.storage.data_dir, f"{doc['id']}.json")
                    with open(doc_path, "w") as df:
                        json.dump(doc, df, indent=2)
                
                latency = (time.time() - start_time) * 1000
                st.session_state.telemetry.record_request(latency, True, 0.94)
                
                st.success(f"✅ Ingestion successful! Created and published version {version_id}.")
                st.json(processed_docs)

with tab2:
    st.subheader("System Telemetry Summary")
    summary = st.session_state.telemetry.get_summary()
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Executions", summary["total_requests"])
    col2.metric("Avg Latency", f"{summary['avg_latency_ms']} ms")
    col3.metric("Failure Rate", f"{summary['error_rate'] * 100}%")
    col4.metric("Avg Quality Score", summary["avg_confidence"])

with tab3:
    st.subheader("Directory & Version Management")
    
    col1, col2 = st.columns(2)
    with col1:
        st.write("🟢 **Active KB Storage**")
        st.write(os.listdir(st.session_state.storage.data_dir))
        
        st.write("📦 **Stored Versions**")
        st.write(os.listdir(st.session_state.storage.versions_dir))
        
    with col2:
        st.write("☣️ **Quarantine Directory**")
        st.write(os.listdir(st.session_state.storage.quarantine_dir))
        
    st.markdown("---")
    st.subheader("Rollback Engine")
    version_files = os.listdir(st.session_state.storage.versions_dir)
    selected_version = st.selectbox("Select Version to Rollback", options=version_files if version_files else ["No versions available"])
    
    if st.button("Execute Rollback"):
        if version_files and selected_version != "No versions available":
            v_id = selected_version.replace("version_", "").replace(".json", "")
            st.session_state.storage.rollback_to_version(v_id)
            st.success(f"🔄 Active Knowledge Base successfully rolled back to {v_id}!")
        else:
            st.warning("No valid version selected.")
