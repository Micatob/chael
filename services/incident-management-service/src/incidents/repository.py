from typing import List, Dict, Any, Optional
from datetime import datetime
from storage.factory import get_storage_client
from models.schema import Incident

class IncidentRepository:
    """
    Repository for persisting and retrieving incidents.
    """
    def __init__(self):
        self.storage = get_storage_client()

    def create(self, incident: Incident) -> Incident:
        """Persist a new incident."""
        return self.storage.index_incident(incident)

    def get_all(self, status: str = None) -> List[Dict[str, Any]]:
        """Retrieve incidents with optional server-side status filter."""
        return self.storage.get_incidents(status=status)

    def get_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific incident by direct lookup."""
        if hasattr(self.storage, "get_incident_by_id"):
            return self.storage.get_incident_by_id(incident_id)
        incidents = self.storage.get_incidents(limit=10000)
        for inc in incidents:
            if inc.get("incident_id") == incident_id:
                return inc
        return None

    def update_status(self, incident_id: str, status: str) -> bool:
        """Update incident status."""
        incident = self.get_by_id(incident_id)
        if incident:
            incident["status"] = status
            self.storage.index_incident(Incident(**incident))
            return True
        return False
