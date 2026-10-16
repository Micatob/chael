# chael-agent (Track B shipper)

Lightweight endpoint agent for [Chael SIEM](https://github.com/Micatob/chael).
It collects host logs and ships them to any Chael SIEM server (Track A standalone).

```bash
pip install chael-agent
chael-agent --siem-url http://<siem-ip>:8001 --mode windows-events
chael-agent --siem-url http://<siem-ip>:8001 --mode linux-syslog
chael-agent --siem-url http://<siem-ip>:8001 --mode tail --paths /var/log/nginx/access.log
```

Full guide: `AGENT_DEPLOYMENT.md` in the repo root.
Server download endpoint (no PyPI needed): `http://<siem-ip>:8001/api/agent/download/`.
