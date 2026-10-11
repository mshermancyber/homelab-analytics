"""Base classes for anomaly detectors."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional


@dataclass
class AnomalyResult:
    """Result from an anomaly detector run.

    Attributes:
        ip: The source IP flagged as anomalous.
        score: Anomaly score (higher = more anomalous).
        details: Feature values and any other per-host context.
        detector_name: Name of the detector that produced this result.
    """
    ip: str
    score: float
    details: Dict[str, Any] = field(default_factory=dict)
    detector_name: str = ""


class BaseAnomalyDetector(ABC):
    """Abstract base class for per-host anomaly detectors.

    Subclasses must implement ``name``, ``description``, ``last_results``,
    ``last_run``, and ``detect()``.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short unique name for this detector (e.g. 'isolation_forest')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what the detector does."""
        ...

    @property
    @abstractmethod
    def last_results(self) -> List[AnomalyResult]:
        """Results from the most recent ``detect()`` call."""
        ...

    @property
    @abstractmethod
    def last_run(self) -> Optional[datetime]:
        """Timestamp of the most recent ``detect()`` call, or None."""
        ...

    @abstractmethod
    async def detect(self) -> List[AnomalyResult]:
        """Run detection and return a list of anomalous hosts."""
        ...

    # ------------------------------------------------------------------
    # Optional model persistence methods (subclasses may override)
    # ------------------------------------------------------------------

    def save_model(self, path: str) -> None:
        """Save the trained model to *path*.  Default no-op."""

    def load_model(self, path: str) -> bool:
        """Load a previously saved model from *path*.

        Returns:
            ``True`` if the model was loaded successfully.
        """
        return False

    def data_hash(self) -> str:
        """Return a stable hash string for the data/parameters this detector
        depends on.  Used for cache keying.  Default: empty string (no cache).
        """
        return ""
