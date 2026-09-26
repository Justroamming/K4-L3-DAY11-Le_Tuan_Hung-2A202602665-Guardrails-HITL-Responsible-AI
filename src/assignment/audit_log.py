"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        if request_id is None:
            request_id = str(uuid.uuid4())
        start_time = datetime.now(timezone.utc).isoformat()
        self._open[request_id] = datetime.now(timezone.utc).timestamp()
        self.logs.append({
            "request_id": request_id,
            "user_id": user_id,
            "input": text,
            "start_time": start_time,
            "end_time": None,
            "blocked": False,
            "layer": None,
            "latency_ms": None,
        })

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        end_time = datetime.now(timezone.utc).isoformat()
        latency_ms = None
        if request_id and request_id in self._open:
            start_ts = self._open.pop(request_id)
            latency_ms = (datetime.now(timezone.utc).timestamp() - start_ts) * 1000

        # Find the matching log entry or create new
        log_entry = None
        if request_id:
            for entry in reversed(self.logs):
                if entry.get("request_id") == request_id:
                    log_entry = entry
                    break
        
        if log_entry:
            log_entry["output"] = text
            log_entry["end_time"] = end_time
            log_entry["blocked"] = blocked
            log_entry["layer"] = layer
            log_entry["latency_ms"] = latency_ms
        else:
            self.logs.append({
                "request_id": request_id or str(uuid.uuid4()),
                "user_id": user_id,
                "input": "",
                "output": text,
                "start_time": end_time,
                "end_time": end_time,
                "blocked": blocked,
                "layer": layer,
                "latency_ms": latency_ms,
            })

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
