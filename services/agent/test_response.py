"""Unit tests for the endpoint response module (no firewall touched)."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import response


class TestExecuteTask:
    def test_unknown_action(self):
        out = response.execute_task({"action": "rm-rf", "target": "x"})
        assert out["success"] is False

    def test_block_missing_ip(self):
        out = response.execute_task({"action": "block", "target": ""})
        assert out["success"] is False

    def test_kill_needs_target(self):
        out = response.execute_task({"action": "kill_process", "target": ""})
        assert out["success"] is False and "process" in out["error"]

    def test_kill_protected_refused(self, monkeypatch):
        called = []
        monkeypatch.setattr(response, "_run", lambda cmd, timeout=15: (called.append(cmd), (True, ""))[1])
        out = response.execute_task({"action": "kill_process", "process": "lsass.exe"})
        assert out["success"] is False and "protected" in out["error"]
        assert called == []

    def test_kill_dispatches_os_command(self, monkeypatch):
        called = []
        monkeypatch.setattr(response, "_run", lambda cmd, timeout=15: (called.append(cmd), (True, ""))[1])
        out = response.execute_task({"action": "kill_process", "process": "evil.exe"})
        assert out["success"] is True and called

    def test_quarantine_missing_file(self):
        out = response.execute_task({"action": "quarantine_file", "path": "/no/such/file-xyz"})
        assert out["success"] is False

    def test_quarantine_moves_and_hashes(self, tmp_path, monkeypatch):
        import hashlib
        victim = tmp_path / "evil.bin"
        victim.write_bytes(b"malware-bytes")
        monkeypatch.setattr(response, "_run", lambda cmd, timeout=15: (True, ""))
        out = response.execute_task({"action": "quarantine_file", "path": str(victim)})
        assert out["success"] is True
        assert out["sha256"] == hashlib.sha256(b"malware-bytes").hexdigest()
        assert not victim.exists()

    def test_delete_persistence_needs_params(self):
        out = response.execute_task({"action": "delete_persistence", "target": "web-01"})
        assert out["success"] is False and "persistence_kind" in out["error"]

    def test_delete_persistence_dispatch(self, monkeypatch):
        called = []
        monkeypatch.setattr(response, "_run", lambda cmd, timeout=15: (called.append(cmd), (True, ""))[1])
        import platform
        if platform.system() == "Windows":
            out = response.execute_task({"action": "delete_persistence",
                                         "persistence_kind": "schtask",
                                         "persistence_name": "EvilTask"})
            assert out["success"] is True and any("schtasks" in c for c in called)
        else:
            out = response.execute_task({"action": "delete_persistence",
                                         "persistence_kind": "unit",
                                         "persistence_name": "evil.service"})
            assert out["success"] is True and any("systemctl" in c for c in called)

    def test_collect_triage_offline_keeps_bundle(self):
        out = response.execute_task({"action": "collect_triage", "target": "h",
                                     "incident_id": ""})
        assert out["success"] is True and out["sha256"]
        assert os.path.isfile(out["bundle"])
        os.remove(out["bundle"])

    def test_collect_triage_uploads_with_ctx(self, monkeypatch):
        import zipfile
        uploaded = {}

        def fake_post(url, files=None, headers=None, timeout=None, verify=None):
            uploaded["url"] = url
            uploaded["files"] = files
            assert zipfile.is_zipfile(__import__("io").BytesIO(files["bundle"][1]))

            class R:
                status_code = 200

                @staticmethod
                def json():
                    return {"evidence": {"evidence_id": "ev-1"}}

            return R()

        monkeypatch.setattr(response.requests, "post", fake_post)
        ctx = {"siem_url": "http://siem:8001", "auth_headers": lambda: {"Authorization": "Bearer x"}}
        out = response.execute_task({"action": "collect_triage", "target": "h",
                                     "incident_id": "inc-1"}, ctx)
        assert out["success"] is True and out["evidence_id"] == "ev-1"
        assert "/api/incidents/inc-1/evidence/bundle" in uploaded["url"]
