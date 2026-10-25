"""Thread-safe in-memory telemetry tracker for PromptFence.

Records actual in-process scan events, decision distributions, finding counts,
and measured execution latencies.

Notice:
Metrics are maintained strictly in-memory per process instance. Counters reset
upon server restart and are not distributed or synchronized across multi-worker clusters.
No simulated historical placeholder data is used.
"""

from __future__ import annotations

import threading
from typing import Dict

from app.schemas import Decision, TelemetryResponse


class TelemetryTracker:
    """Thread-safe collector for real scan telemetry metrics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total_scans: int = 0
        self._allowed_count: int = 0
        self._reviewed_count: int = 0
        self._blocked_count: int = 0
        self._total_findings: int = 0
        self._cumulative_latency_ms: float = 0.0
        self._last_latency_ms: float = 0.0

    def record_scan(self, decision: str, findings_count: int, latency_ms: float) -> None:
        """Record an actual scan execution event."""
        with self._lock:
            self._total_scans += 1
            self._total_findings += findings_count
            self._cumulative_latency_ms += latency_ms
            self._last_latency_ms = latency_ms

            dec = str(decision).lower()
            if dec == Decision.ALLOW.value:
                self._allowed_count += 1
            elif dec == Decision.REVIEW.value:
                self._reviewed_count += 1
            elif dec == Decision.BLOCK.value:
                self._blocked_count += 1

    def get_metrics(self) -> TelemetryResponse:
        """Retrieve current in-process telemetry snapshot."""
        with self._lock:
            avg_lat = (
                (self._cumulative_latency_ms / self._total_scans)
                if self._total_scans > 0
                else 0.0
            )
            return TelemetryResponse(
                total_scans=self._total_scans,
                allowed_count=self._allowed_count,
                reviewed_count=self._reviewed_count,
                blocked_count=self._blocked_count,
                total_findings=self._total_findings,
                avg_latency_ms=round(avg_lat, 3),
                last_latency_ms=round(self._last_latency_ms, 3),
            )

    def reset(self) -> None:
        """Reset in-memory counters to zero (used primarily for test isolation)."""
        with self._lock:
            self._total_scans = 0
            self._allowed_count = 0
            self._reviewed_count = 0
            self._blocked_count = 0
            self._total_findings = 0
            self._cumulative_latency_ms = 0.0
            self._last_latency_ms = 0.0


# In-process singleton instance
telemetry = TelemetryTracker()
