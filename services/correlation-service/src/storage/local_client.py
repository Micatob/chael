import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from models.schema import NormalizedLog, Incident

class LocalStorageClient:
    def __init__(self):
        self.data_dir = "data"
        self.logs_file = os.path.join(self.data_dir, "logs.json")
        self.incidents_file = os.path.join(self.data_dir, "incidents.json")
        self._ensure_storage()

    def _ensure_storage(self):
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        if not os.path.exists(self.logs_file):
            with open(self.logs_file, "w") as f:
                json.dump([], f)
        if not os.path.exists(self.incidents_file):
            with open(self.incidents_file, "w") as f:
                json.dump([], f)

    def _read_file(self, path) -> List[Dict]:
        try:
            with open(path, "r") as f:
                return json.load(f)
        except:
            return []

    def _append_file(self, path, item: Dict):
        data = self._read_file(path)
        data.append(item)
        with open(path, "w") as f:
            json.dump(data, f, default=str)

    def ensure_indices(self):
        self._ensure_storage()

    def index_log(self, log: NormalizedLog):
        # Convert to dict and Handle datetime serialization for JSON
        data = log.model_dump()
        data['timestamp'] = data['timestamp'].isoformat()
        self._append_file(self.logs_file, data)

    def index_incident(self, incident: Incident):
        data = incident.model_dump()
        data['timestamp'] = data['timestamp'].isoformat()
        self._append_file(self.incidents_file, data)

    def update_incident_status(self, incident_id: str, status: str):
        data = self._read_file(self.incidents_file)
        for inc in data:
            if inc.get('incident_id') == incident_id:
                inc['status'] = status
                break
        with open(self.incidents_file, "w") as f:
            json.dump(data, f, default=str)

    def get_logs(self) -> List[Dict]:
        return self._read_file(self.logs_file)

    def get_logs_filtered(
        self,
        limit: int = 100,
        offset: int = 0,
        search: Optional[str] = None,
        severity: Optional[str] = None,
        host: Optional[str] = None,
        source: Optional[str] = None,
        sort_by: str = "timestamp",
        sort_order: str = "desc"
    ) -> List[Dict]:
        """Fetch logs with advanced filtering, pagination, and sorting."""
        logs = self._read_file(self.logs_file)

        # Apply filters
        if search:
            search_lower = search.lower()
            logs = [log for log in logs if
                   search_lower in log.get('message', '').lower() or
                   search_lower in log.get('host', '').lower() or
                   search_lower in log.get('source', '').lower()]

        if severity:
            logs = [log for log in logs if log.get('severity') == severity]

        if host:
            logs = [log for log in logs if log.get('host') == host]

        if source:
            logs = [log for log in logs if log.get('source') == source]

        # Sort logs
        reverse = sort_order == "desc"
        if sort_by == "timestamp":
            logs.sort(key=lambda x: x.get('timestamp', ''), reverse=reverse)
        elif sort_by == "severity":
            severity_order = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'UNKNOWN': 1}
            logs.sort(key=lambda x: severity_order.get(x.get('severity', 'UNKNOWN'), 0), reverse=reverse)
        else:
            logs.sort(key=lambda x: x.get(sort_by, ''), reverse=reverse)

        # Apply pagination
        return logs[offset:offset + limit]

    def get_incidents(self) -> List[Dict]:
        return self._read_file(self.incidents_file)
