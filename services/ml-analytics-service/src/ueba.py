import logging
import pandas as pd
import requests
from datetime import datetime, timezone, timedelta
from opensearchpy import OpenSearch
from sklearn.ensemble import IsolationForest
from config import settings

logger = logging.getLogger("ueba_engine")

class UEBAEngine:
    def __init__(self):
        self.os_client = self._init_opensearch()
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.last_run: str | None = None
        self.last_status: str = "never"
        self.last_anomaly_count: int = 0
        self.last_anomalies: list[dict] = []
        
    def _init_opensearch(self):
        try:
            return OpenSearch(
                hosts=[{"host": settings.OPENSEARCH_HOST, "port": settings.OPENSEARCH_PORT}],
                http_auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD),
                use_ssl=settings.OPENSEARCH_USE_SSL,
                verify_certs=settings.OPENSEARCH_VERIFY_CERTS,
                ssl_assert_hostname=False,
                ssl_show_warn=False,
            )
        except Exception as e:
            logger.error(f"Failed to connect to OpenSearch: {e}")
            return None

    def fetch_recent_logs(self, hours=24):
        if not self.os_client:
            return []
            
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(hours=hours)
        
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_time.isoformat(),
                        "lte": now.isoformat()
                    }
                }
            },
            "size": 10000,
            "_source": ["timestamp", "source_logs", "metadata"]
        }
        
        try:
            # We match the general logs index
            response = self.os_client.search(index="chaelsiem-logs-*", body=query, ignore_unavailable=True)
            return [hit["_source"] for hit in response.get("hits", {}).get("hits", [])]
        except Exception as e:
            logger.error(f"Error fetching logs for UEBA: {e}")
            return []

    def extract_features(self, logs):
        # Extract meaningful numeric features per user
        data = []
        for log in logs:
            meta = log.get("metadata", {})
            user = meta.get("user", "unknown")
            if user == "unknown":
                continue
                
            data.append({
                "user": user,
                "is_failed_auth": 1 if meta.get("auth_result") == "failure" else 0,
                "is_success_auth": 1 if meta.get("auth_result") == "success" else 0,
                "count": 1
            })
            
        df = pd.DataFrame(data)
        if df.empty:
            return pd.DataFrame()
            
        # Group by user and aggregate
        features = df.groupby("user").agg({
            "count": "sum",
            "is_failed_auth": "sum",
            "is_success_auth": "sum"
        }).reset_index()
        
        # Calculate derived features
        features["fail_ratio"] = features["is_failed_auth"] / features["count"]
        return features

    def run_analysis(self):
        logger.info("Running UEBA anomaly detection cycle...")
        self.last_run = datetime.now(timezone.utc).isoformat()
        logs = self.fetch_recent_logs(hours=24)
        if not logs:
            logger.info("No logs found for analysis.")
            self.last_status = "no_data"
            self.last_anomaly_count = 0
            self.last_anomalies = []
            return
            
        features_df = self.extract_features(logs)
        if features_df.empty or len(features_df) < 5:
            logger.info("Not enough user activity data to train UEBA model (need >= 5 users).")
            self.last_status = "insufficient_data"
            self.last_anomaly_count = 0
            self.last_anomalies = []
            return
            
        # Select numeric columns for Isolation Forest
        X = features_df[["count", "is_failed_auth", "fail_ratio"]]
        
        # Fit and predict
        self.model.fit(X)
        features_df["anomaly"] = self.model.predict(X)
        
        # Anomalies are marked as -1
        anomalies = features_df[features_df["anomaly"] == -1]
        self.last_anomaly_count = len(anomalies)
        self.last_anomalies = anomalies.to_dict(orient="records") if not anomalies.empty else []
        
        if not anomalies.empty:
            logger.warning(f"Detected {len(anomalies)} anomalous users!")
            self.last_status = "anomalies_found"
            self._report_anomalies(anomalies)
        else:
            logger.info("No anomalies detected.")
            self.last_status = "clean"

    def _report_anomalies(self, anomalies_df):
        for _, row in anomalies_df.iterrows():
            user = row["user"]
            desc = (
                f"UEBA Anomaly Detected for user '{user}': "
                f"{int(row['count'])} total actions, "
                f"{int(row['is_failed_auth'])} failed authentications "
                f"({(row['fail_ratio']*100):.1f}% fail rate)."
            )
            
            payload = {
                "source_logs": [],
                "description": desc,
                "risk_score": 85,
                "status": "OPEN",
                "artifacts": {
                    "attack_type": "ueba_anomaly",
                    "user": user,
                    "fail_ratio": row["fail_ratio"]
                }
            }
            
            try:
                url = f"{settings.INCIDENT_SERVICE_URL}/api/incidents/create"
                response = requests.post(url, json=payload, timeout=10)
                response.raise_for_status()
                logger.info(f"Reported UEBA anomaly for {user} to Incident Service.")
            except Exception as e:
                logger.error(f"Failed to report anomaly for {user}: {e}")
