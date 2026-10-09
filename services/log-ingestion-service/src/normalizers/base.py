from abc import ABC, abstractmethod
from typing import Any, Optional, Dict
from models.schema import NormalizedLog

class BaseNormalizer(ABC):
    @abstractmethod
    def normalize(self, raw_log: Any) -> Optional[NormalizedLog]:
        """Parse raw log into a NormalizedLog object."""
        pass
