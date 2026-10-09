import pandas as pd
from unittest.mock import patch, MagicMock


class TestFeatureExtraction:
    def test_extract_features_from_logs(self, engine):
        logs = [
            {"metadata": {"user": "alice", "auth_result": "failure"}},
            {"metadata": {"user": "alice", "auth_result": "failure"}},
            {"metadata": {"user": "bob", "auth_result": "success"}},
            {"metadata": {"user": "charlie", "auth_result": "failure"}},
        ]
        features = engine.extract_features(logs)
        assert not features.empty
        assert "user" in features.columns
        assert "count" in features.columns
        assert "fail_ratio" in features.columns

        alice = features[features["user"] == "alice"]
        assert alice["count"].values[0] == 2
        assert alice["fail_ratio"].values[0] == 1.0

        bob = features[features["user"] == "bob"]
        assert bob["fail_ratio"].values[0] == 0.0

    def test_skip_unknown_users(self, engine):
        logs = [
            {"metadata": {"user": "unknown", "auth_result": "failure"}},
            {"metadata": {"user": "unknown"}},
        ]
        features = engine.extract_features(logs)
        assert features.empty

    def test_empty_logs_returns_empty(self, engine):
        features = engine.extract_features([])
        assert features.empty

    def test_logs_without_metadata_still_process(self, engine):
        logs = [
            {"metadata": {"user": "alice"}},
            {"metadata": {"user": "bob"}},
        ]
        features = engine.extract_features(logs)
        assert not features.empty
        assert len(features) == 2


def _patch_engine_search(engine_obj, logs):
    target = engine_obj.os_client if engine_obj.os_client else None
    if target is None:
        return patch.object(type(engine_obj), "fetch_recent_logs", return_value=logs)
    return patch.object(target, "search", return_value={"hits": {"hits": [{"_source": log} for log in logs]}})


class TestAnomalyDetection:
    def test_run_analysis_with_anomalies(self, engine):
        test_logs = []
        for i in range(50):
            test_logs.append({"metadata": {"user": f"normal-user-{i % 10}", "auth_result": "success"}})
        for i in range(5):
            test_logs.append({"metadata": {"user": "attacker", "auth_result": "failure"}})

        with _patch_engine_search(engine, test_logs):
            engine.run_analysis()

        assert engine.last_status in ("anomalies_found", "clean", "insufficient_data")
        assert engine.last_run is not None

    def test_run_analysis_no_logs(self, engine):
        with _patch_engine_search(engine, []):
            engine.run_analysis()
        assert engine.last_status == "no_data"

    def test_anomaly_reporting(self, engine):
        anomalies_df = pd.DataFrame([{
            "user": "suspicious_user",
            "count": 100,
            "is_failed_auth": 95,
            "fail_ratio": 0.95,
            "anomaly": -1,
        }])
        with patch("requests.post") as mock_post:
            mock_post.return_value.status_code = 200
            engine._report_anomalies(anomalies_df)
            mock_post.assert_called_once()


def test_anomaly_detection_with_mocked_opensearch(engine):
    test_logs = []
    for i in range(30):
        test_logs.append({"metadata": {"user": f"user{i % 5}", "auth_result": "success"}})
    test_logs.append({"metadata": {"user": "attacker", "auth_result": "failure"}})
    test_logs.append({"metadata": {"user": "attacker", "auth_result": "failure"}})
    test_logs.append({"metadata": {"user": "attacker", "auth_result": "failure"}})

    with _patch_engine_search(engine, test_logs):
        engine.run_analysis()
        assert engine.last_status in ("anomalies_found", "clean", "insufficient_data")
        assert engine.last_run is not None
