from config import settings
from .opensearch_client import OpenSearchClient
from .local_client import LocalStorageClient
from typing import Union, Optional
import logging
import threading

logger = logging.getLogger(__name__)

class StorageFactory:
    _instance: Optional[Union[OpenSearchClient, LocalStorageClient]] = None
    _lock = threading.Lock()

    @classmethod
    def get_client(cls) -> Union[OpenSearchClient, LocalStorageClient]:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    try:
                        if settings.STORAGE_TYPE == "opensearch":
                            logger.info("Initializing OpenSearch Storage Client...")
                            cls._instance = OpenSearchClient()
                        else:
                            logger.info("Initializing Local Storage Client...")
                            cls._instance = LocalStorageClient()
                    except Exception as e:
                        logger.error(f"Failed to initialize storage client: {e}")
                        logger.warning("Falling back to Local Storage Client due to initialization error.")
                        cls._instance = LocalStorageClient()
        return cls._instance

def get_storage_client():
    return StorageFactory.get_client()
