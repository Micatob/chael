import React, { useEffect, useState, lazy, Suspense } from 'react';
import { apiService } from '../services/api';
import { wsService } from '../services/websocket';

const ReactECharts = lazy(() => import('echarts-for-react'));

interface Agent {
  agent_id: string;
  hostname: string;
  last_seen: string;
  current_version: string;
  online: boolean;
}

const Agents: React.FC = () => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hostname, setHostname] = useState('');
  const [newAgentResult, setNewAgentResult] = useState<{ agent_id: string; agent_key: string } | null>(null);

  const [refreshing, setRefreshing] = useState(false);
  const [heartbeat, setHeartbeat] = useState<Array<{ timestamp: string }>>([]);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);

  const fetchData = async (silent = false) => {
    if (!silent) setLoading(true);
    else setRefreshing(true);
    setError(null);
    try {
      const agentsRes = await apiService.listAgents();
      setAgents(agentsRes.data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load data');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const fetchHeartbeat = async (agentId: string) => {
    try {
      const res = await apiService.getAgentHeartbeats(agentId, 50);
      setHeartbeat(res.data || []);
      setSelectedAgent(agentId);
    } catch {
      setHeartbeat([]);
      setSelectedAgent(agentId);
    }
  };

  useEffect(() => {
    fetchData();
    // Live: poll every 30s + WS agent events (no full-page spinner on poll)
    const interval = setInterval(() => fetchData(true), 30000);
    const token = localStorage.getItem('s2_token');
    wsService.connect(token ?? undefined);
    const onAgent = () => fetchData(true);
    wsService.on('agent:status', onAgent);
    wsService.on('agent:heartbeat', onAgent);
    return () => {
      clearInterval(interval);
      wsService.off('agent:status', onAgent);
      wsService.off('agent:heartbeat', onAgent);
    };
  }, []);

  const handleRevokeAgent = async (agentId: string) => {
    if (!window.confirm(`Revoke agent ${agentId.slice(0, 8)}...? This will prevent it from authenticating.`)) return;
    try {
      await apiService.revokeAgent(agentId);
      fetchData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to revoke agent');
    }
  };

  const handleDeleteAgent = async (agentId: string) => {
    if (!window.confirm(`Permanently delete agent ${agentId.slice(0, 8)}...? This cannot be undone. The agent will be removed from the system.`)) return;
    try {
      await apiService.deleteAgent(agentId);
      fetchData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to delete agent');
    }
  };

  const handlePurgeAll = async () => {
    if (!window.confirm('Permanently DELETE ALL registered agents? This cannot be undone.')) return;
    try {
      await apiService.purgeAllAgents();
      setAgents([]);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to purge agents');
    }
  };

  const handleRotateKey = async (agentId: string) => {
    try {
      const res = await apiService.rotateAgentKey(agentId);
      setNewAgentResult({ agent_id: res.data.agent_id, agent_key: res.data.agent_key });
      fetchData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to rotate key');
    }
  };

  const handleMarkOnline = async (agentId: string) => {
    try {
      await apiService.markAgentOnline(agentId);
      fetchData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to mark agent online');
    }
  };

  const handleDirectRegister = async () => {
    if (!hostname.trim()) return;
    try {
      const res = await apiService.registerAgent(hostname.trim());
      setNewAgentResult({ agent_id: res.data.agent_id, agent_key: res.data.agent_key });
      setHostname('');
      fetchData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to register agent');
    }
  };

  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = async (text: string, key = 'default') => {
    let ok = false;
    try {
      if (navigator.clipboard && window.isSecureContext !== false) {
        await navigator.clipboard.writeText(text);
        ok = true;
      }
    } catch {
      ok = false;
    }
    if (!ok) {
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        ok = document.execCommand('copy');
        document.body.removeChild(ta);
      } catch {
        ok = false;
      }
    }
    if (ok) {
      setCopiedKey(key);
      window.setTimeout(() => setCopiedKey((k) => (k === key ? null : k)), 1600);
    } else {
      // Last-resort: select via prompt so analyst can Ctrl+C manually
      window.prompt('Copy manually (Ctrl+C):', text);
    }
  };

  const timeAgo = (isoStr: string) => {
    if (!isoStr) return 'never';
    const diff = Date.now() - new Date(isoStr).getTime();
    const seconds = Math.floor(diff / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  };

  const getSiemHost = () => window.location.hostname;

  const getPowershellCmd = (agentId: string, agentKey: string) => {
    const host = getSiemHost();
    const siemUrl = `http://${host}:8001`;
    const scriptUrl = `${siemUrl}/api/agent/static/deploy-agent.ps1`;
    return `Set-ExecutionPolicy Bypass -Scope Process -Force; iwr -Uri "${scriptUrl}" -OutFile "$env:TEMP\\deploy.ps1" -UseBasicParsing; & "$env:TEMP\\deploy.ps1" -SiemUrl "${siemUrl}" -AgentId "${agentId}" -AgentKey "${agentKey}" -NoSSLVerify; Remove-Item "$env:TEMP\\deploy.ps1" -Force`;
  };

  if (loading && agents.length === 0) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-12 h-12 border-2 rounded-full animate-spin mx-auto" style={{ borderColor: 'rgba(75,85,99,0.2)', borderTopColor: '#60a5fa' }} />
          <p className="mt-4 text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Loading agents...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold tracking-wider" style={{ color: '#d1d5db' }}>AGENT MANAGEMENT</h1>
        <div className="flex gap-2 items-center">
          <span className="text-xs" style={{ color: '#6b7280' }}>
            {wsService.isConnected() ? 'Live: WS' : 'Live: polling 30s'}
          </span>
          <button
            onClick={() => fetchData(true)}
            disabled={refreshing || loading}
            style={{ border: '1px solid #333', color: '#9ca3af', background: 'transparent', padding: '4px 12px', borderRadius: '4px', fontSize: '12px', opacity: (refreshing || loading) ? 0.4 : 1 }}
          >
            {(refreshing || loading) ? 'Syncing...' : 'Refresh'}
          </button>
          {agents.length > 0 && (
            <button
              onClick={handlePurgeAll}
              style={{ border: '1px solid #7f1d1d', color: '#ef4444', background: 'transparent', padding: '4px 12px', borderRadius: '4px', fontSize: '12px' }}
            >
              Purge All
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="text-red-500 text-sm border border-red-900/50 p-3 bg-red-950/20 rounded">
          {error}
        </div>
      )}

      {newAgentResult && (
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
          <div className="font-bold mb-2" style={{ color: '#60a5fa' }}>Agent Registered — Save These Credentials</div>
          <div className="space-y-2 text-sm font-mono mb-3">
            <div className="flex items-center gap-2">
              <span style={{ color: '#6b7280' }}>Agent ID:</span>
              <code className="flex-1 p-1 rounded" style={{ background: 'rgba(0,0,0,0.3)', color: '#d1d5db' }}>{newAgentResult.agent_id}</code>
              <button onClick={() => copyToClipboard(newAgentResult.agent_id, 'id')} style={{ border: '1px solid #333', color: copiedKey === 'id' ? '#22c55e' : '#9ca3af', background: '#0a0a0a', padding: '2px 8px', borderRadius: '4px', fontSize: '13px' }}>{copiedKey === 'id' ? 'Copied!' : 'Copy'}</button>
            </div>
            <div className="flex items-center gap-2">
              <span style={{ color: '#6b7280' }}>Agent Key:</span>
              <code className="flex-1 p-1 rounded" style={{ background: 'rgba(0,0,0,0.3)', color: '#d1d5db' }}>{newAgentResult.agent_key}</code>
              <button onClick={() => copyToClipboard(newAgentResult.agent_key, 'key')} style={{ border: '1px solid #333', color: copiedKey === 'key' ? '#22c55e' : '#9ca3af', background: '#0a0a0a', padding: '2px 8px', borderRadius: '4px', fontSize: '13px' }}>{copiedKey === 'key' ? 'Copied!' : 'Copy'}</button>
            </div>
          </div>
          <div className="text-xs mb-2" style={{ color: '#f59e0b' }}>
            This key will not be shown again. Store it securely.
          </div>
          <div className="flex items-center justify-between gap-2 mb-2">
            <div className="text-xs" style={{ color: '#6b7280' }}>
              PowerShell one-liner (copy &amp; paste on target Windows machine):
            </div>
            <button
              onClick={() => copyToClipboard(getPowershellCmd(newAgentResult.agent_id, newAgentResult.agent_key), 'ps')}
              style={{ border: '1px solid #333', color: copiedKey === 'ps' ? '#22c55e' : '#d1d5db', background: '#1a1a1a', padding: '4px 12px', borderRadius: '4px', fontSize: '13px', fontWeight: 700, flexShrink: 0 }}
            >
              {copiedKey === 'ps' ? 'Copied!' : 'Copy command'}
            </button>
          </div>
          <div style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px' }}>
            <code className="block p-3 rounded text-xs break-all leading-relaxed" style={{ color: '#d1d5db', paddingRight: '12px' }}>
              {getPowershellCmd(newAgentResult.agent_id, newAgentResult.agent_key)}
            </code>
          </div>
          <button onClick={() => setNewAgentResult(null)} className="mt-3" style={{ border: '1px solid #333', color: '#9ca3af', background: 'transparent', padding: '4px 12px', borderRadius: '4px', fontSize: '12px' }}>Dismiss</button>
        </div>
      )}

      {/* Direct Agent Registration */}
      <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
        <div className="text-xs font-bold uppercase mb-4" style={{ color: '#6b7280' }}>Register Agent Directly</div>
        <div className="flex gap-2">
          <input
            type="text"
            value={hostname}
            onChange={e => setHostname(e.target.value)}
            placeholder="agent-hostname"
            className="text-xs rounded px-2 py-1 flex-1"
            style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
            onKeyDown={e => e.key === 'Enter' && handleDirectRegister()}
          />
          <button
            onClick={handleDirectRegister}
            disabled={!hostname.trim()}
            style={{ border: '1px solid #333', color: '#9ca3af', background: 'transparent', padding: '4px 12px', borderRadius: '4px', fontSize: '12px' }}
          >
            Register
          </button>
        </div>
      </div>

      {/* Registered Agents */}
      <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
        <div className="text-xs font-bold uppercase mb-4" style={{ color: '#6b7280' }}>Registered Agents ({agents.length})</div>
        {agents.length === 0 ? (
          <p className="text-sm" style={{ color: '#6b7280' }}>No agents registered yet.</p>
        ) : (
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {[...agents].sort((a, b) => (a.online === b.online ? 0 : a.online ? -1 : 1)).map((a) => (
              <div
                key={a.agent_id}
                className="flex items-center justify-between p-3 rounded"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span
                      className="inline-block w-2 h-2 rounded-full"
                      style={{ backgroundColor: a.online ? '#22c55e' : '#ef4444' }}
                      title={a.online ? 'Online' : 'Offline'}
                    />
                    <span className="text-sm font-bold" style={{ color: '#d1d5db' }}>{a.hostname}</span>
                    <div
                      style={{
                        background: a.online ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)',
                        color: a.online ? '#22c55e' : '#ef4444',
                        padding: '2px 6px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: 700,
                        letterSpacing: '0.05em',
                      }}
                    >
                      {a.online ? 'ONLINE' : 'OFFLINE'}
                    </div>
                    <div style={{ background: 'rgba(96,165,250,0.15)', color: '#60a5fa', padding: '2px 6px', borderRadius: '4px', fontSize: '11px', fontWeight: 700, letterSpacing: '0.05em' }}>AGENT</div>
                  </div>
                  <code className="text-xs" style={{ color: '#6b7280' }}>{a.agent_id}</code>
                  <div className="text-xs mt-1" style={{ color: '#6b7280' }}>
                    last seen: {timeAgo(a.last_seen)}{a.current_version ? ` · v${a.current_version}` : ''}
                  </div>
                </div>
<div className="flex gap-2">
                   <button onClick={() => fetchHeartbeat(a.agent_id)} style={{ border: '1px solid #333', color: '#60a5fa', background: 'transparent', padding: '4px 12px', borderRadius: '4px', fontSize: '12px' }}>
                     Heartbeat
                   </button>
                   {!a.online && (
                     <button onClick={() => handleMarkOnline(a.agent_id)} style={{ border: '1px solid #22c55e', color: '#22c55e', background: 'transparent', padding: '4px 12px', borderRadius: '4px', fontSize: '12px' }}>
                       Mark Online
                     </button>
                   )}
                   <button onClick={() => handleRotateKey(a.agent_id)} style={{ border: '1px solid #333', color: '#9ca3af', background: 'transparent', padding: '4px 12px', borderRadius: '4px', fontSize: '12px' }}>
                     Rotate
                   </button>
                   <button onClick={() => handleRevokeAgent(a.agent_id)} style={{ border: '1px solid #7f1d1d', color: '#ef4444', background: 'transparent', padding: '4px 12px', borderRadius: '4px', fontSize: '12px' }}>
                     Revoke
                   </button>
                   <button onClick={() => handleDeleteAgent(a.agent_id)} style={{ border: '1px solid #7f1d1d', color: '#ef4444', background: 'rgba(127,29,29,0.4)', padding: '4px 12px', borderRadius: '4px', fontSize: '12px' }}>
                     Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Heartbeat history — per-agent last 50 beats */}
      {selectedAgent && (
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
          <div className="flex items-center justify-between mb-3">
            <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>
              Heartbeat history — {selectedAgent.slice(0, 8)}… ({heartbeat.length} beats)
            </div>
            <button onClick={() => setSelectedAgent(null)} style={{ border: '1px solid #333', color: '#9ca3af', background: 'transparent', padding: '4px 12px', borderRadius: '4px', fontSize: '12px' }}>
              Close
            </button>
          </div>
          {heartbeat.length === 0 ? (
            <p className="text-sm" style={{ color: '#6b7280' }}>No heartbeat records yet — agent offline or never checked in.</p>
          ) : (
            <Suspense fallback={<div className="text-xs" style={{ color: '#6b7280' }}>Loading chart...</div>}>
              <ReactECharts
                option={{
                  tooltip: { trigger: 'axis' },
                  grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
                  xAxis: {
                    type: 'category',
                    data: heartbeat.map((h) => new Date(h.timestamp).toLocaleTimeString()),
                    axisLabel: { color: '#9ca3af', fontSize: 10 },
                  },
                  yAxis: { type: 'value', min: 0, max: 1, axisLabel: { color: '#9ca3af' }, splitLine: { lineStyle: { color: '#374151' } } },
                  series: [{
                    data: heartbeat.map(() => 1),
                    type: 'bar' as const,
                    itemStyle: { color: '#22c55e', borderRadius: [3, 3, 0, 0] },
                  }],
                }}
                style={{ height: '220px' }}
              />
            </Suspense>
          )}
        </div>
      )}
    </div>
  );
};

export default Agents;
