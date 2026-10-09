from abc import ABC, abstractmethod
from typing import List, Dict, Any


class BaseFeed(ABC):
    @abstractmethod
    def poll(self) -> List[Dict[str, Any]]:
        pass
