import React, { useEffect, useState } from 'react';
import { Zap, Clock, History, Bell, RefreshCw, Shield, ArrowLeft } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';
import type { SOARHistoryEntry, PendingAction } from '../types';

const statusColors: Record<string, { color: string; bg: string }> = {
  PENDING: { color: '#ff9500', bg: 'rgba(255,149,0,0.12)' },
  APPROVED: { color: '#60a5fa', bg: 'rgba(96,165,250,0.12)' },
  REJECTED: { color: '#ff2d55', bg: 'rgba(255,45,85,0.12)' },
  EXECUTED: { color: '#30d158', bg: 'rgba(48,209,88,0.12)' },
  FAILED: { color: '#ff2d55', bg: 'rgba(255,45,85,0.12)' },
};

const inputStyle: React.CSSProperties = {
  background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db',
};
const cardStyle: React.CSSProperties = {
  background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)',
};

const SOAR: React.FC = () => {
  const navigate = useNavigate();
  const [history, setHistory] = useState<SOARHistoryEntry[]>([]);
  const [pendingActions, setPendingActions] = useState<PendingAction[]>([]);
  const [pendingIncidentId, setPendingIncidentId] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [notifChannel, setNotifChannel] = useState('SIEM');
  const [notifEnabled, setNotifEnabled] = useState(true);
  const [notifConfig, setNotifConfig] = useState('{}');
  const [notifResult, setNotifResult] = useState<string | null>(null);
  const [registering, setRegistering] = useState(false);

  const [rules, setRules] = useState<any[]>([]);
  const [togglingRule, setTogglingRule] = useState<string | null>(null);
  const [rulesLoading, setRulesLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [actingId, setActingId] = useState<string | null>(null);

  // Endpoint response (remote contain / recover via agent task-pull)
  const [agentTasks, setAgentTasks] = useState<any[]>([]);
  const [taskAction, setTaskAction] = useState('isolate');
  const [taskTarget, setTaskTarget] = useState('');
  const [taskHost, setTaskHost] = useState('');
  const [queueing, setQueueing] = useState(false);

  const fetchAgentTasks = async () => {
    try {
      const res = await apiService.listAgentTasks();
      setAgentTasks(res.data.tasks || []);
    } catch { /* older backend without task queue */ }
  };

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiService.getSOARHistory();
      setHistory(res.data.history || []);
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'Failed to load SOAR history');
    } finally {
      setLoading(false);
    }
  };

  const fetchRules = async () => {
    setRulesLoading(true);
    try {
      const res = await apiService.listCorrelationRules();
      setRules(res.data || []);
    } catch {} finally { setRulesLoading(false); }
  };

  const fetchAllPending = async () => {
    try {
      const res = await apiService.getAllSOARPending();
      setPendingActions((res.data.pending_actions || []) as any);
    } catch {
      // Backend may be older without /pending — keep per-incident search working
    }
  };

  const handleRefreshAll = async () => {
    setRefreshing(true);
    setError(null);
    try {
      await Promise.allSettled([fetchHistory(), fetchRules(), fetchAllPending(), fetchAgentTasks()]);
      if (pendingIncidentId.trim()) await fetchPendingActions();
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => { fetchHistory(); fetchRules(); fetchAllPending(); fetchAgentTasks(); }, []);

  const handleQueueTask = async () => {
    if (!taskTarget.trim()) { setError('Endpoint response needs a target host or IP'); return; }
    setQueueing(true); setError(null);
    try {
      await apiService.queueAgentTask({
        action: taskAction, target: taskTarget.trim(),
        hostname: taskHost.trim() || undefined,
        incident_id: pendingIncidentId.trim() || undefined,
      });
      setTaskTarget(''); setTaskHost('');
      await fetchAgentTasks();
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'Failed to queue task');
    } finally { setQueueing(false); }
  };

  const handleRecover = async (kind: 'unisolate' | 'unblock', target: string) => {
    if (!target || !window.confirm(`${kind === 'unisolate' ? 'Release isolation for' : 'Remove block on'} ${target}?`)) return;
    setError(null);
    try {
      if (kind === 'unisolate') await apiService.unisolateHost(target);
      else await apiService.unblockIp(target);
      await fetchHistory();
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'Recovery failed');
    }
  };

  const fetchPendingActions = async () => {
    if (!pendingIncidentId.trim()) {
      // No ID typed: fall back to global approval queue
      await fetchAllPending();
      return;
    }
    setError(null);
    try {
      const res = await apiService.getSOARPendingActions(pendingIncidentId.trim());
      setPendingActions(res.data.pending_actions || []);
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'Failed to load pending actions');
      setPendingActions([]);
    }
  };

  const handleApprove = async (incidentId: string, actionId: string) => {
    setActingId(actionId);
    try {
      const res = await apiService.approveSOARAction(incidentId, actionId);
      if (res.data.status === 'approved') { await fetchAllPending(); if (pendingIncidentId.trim()) await fetchPendingActions(); await fetchHistory(); }
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'Failed to approve action');
    } finally {
      setActingId(null);
    }
  };

  const handleReject = async (incidentId: string, actionId: string) => {
    if (!window.confirm('Reject this action? It will never execute.')) return;
    setActingId(actionId);
    try {
      await apiService.rejectSOARAction(incidentId, actionId);
      await fetchAllPending(); if (pendingIncidentId.trim()) await fetchPendingActions(); await fetchHistory();
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'Failed to reject action');
    } finally {
      setActingId(null);
    }
  };

  const handleExportHistory = () => {
    const rows = [['timestamp', 'incident_id', 'action', 'status', 'actor']];
    history.forEach((h: any) => {
      rows.push([h.timestamp || '', h.incident_id || '', h.action || h.action_id || '', h.status || '', h.actor || h.approved_by || '']);
    });
    const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soar_history_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleRegisterNotification = async () => {
    setError(null); setNotifResult(null);
    let parsedConfig: Record<string, any>;
    try { parsedConfig = JSON.parse(notifConfig); } catch { setError('Notification config must be valid JSON'); return; }
    setRegistering(true);
    try {
      const res = await apiService.registerNotificationChannel({ channel: notifChannel, enabled: notifEnabled, config: parsedConfig });
      setNotifResult(`Channel "${res.data.channel}" registered successfully`);
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'Failed to register notification channel');
    } finally { setRegistering(false); }
  };

  const handleToggleRule = async (ruleId: string) => {
    setTogglingRule(ruleId);
    try {
      await apiService.toggleCorrelationRule(ruleId);
      setRules(prev => prev.map(r => r.id === ruleId ? { ...r, enabled: !r.enabled } : r));
    } catch (e) { console.error('Toggle failed', e); } finally { setTogglingRule(null); }
  };

  return (
    <div>
      <div className="space-y-6 max-w-6xl mx-auto">
        <button onClick={() => navigate('/dashboard')} className="flex items-center gap-2 text-xs tracking-widest uppercase transition-colors" style={{ color: '#6b7280' }}
          onMouseEnter={e => (e.currentTarget.style.color = '#9ca3af')} onMouseLeave={e => (e.currentTarget.style.color = '#6b7280')}>
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </button>

        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2" style={{ color: '#d1d5db' }}>
              <Zap className="w-6 h-6" style={{ color: '#60a5fa' }} /> SOAR Management
            </h1>
            <p className="text-sm mt-1" style={{ color: '#6b7280' }}>Automated response actions, pending approvals, and notification channels</p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={handleExportHistory} disabled={history.length === 0} className="flex items-center gap-2 text-xs px-3 py-1.5 rounded transition-colors disabled:opacity-40" style={{ border: '1px solid #333', color: '#9ca3af' }}>
              Export CSV
            </button>
            <button onClick={handleRefreshAll} disabled={refreshing || loading || rulesLoading} className="flex items-center gap-2 text-xs px-3 py-1.5 rounded transition-colors disabled:opacity-40" style={{ border: '1px solid #333', color: '#9ca3af' }}
              onMouseEnter={e => { e.currentTarget.style.color = '#d1d5db'; e.currentTarget.style.borderColor = '#555'; }} onMouseLeave={e => { e.currentTarget.style.color = '#9ca3af'; e.currentTarget.style.borderColor = '#333'; }}>
              <RefreshCw className="w-3.5 h-3.5" /> {(refreshing || loading) ? 'Syncing...' : 'Refresh'}
            </button>
          </div>
        </div>

        {error && (
          <div className="rounded-lg px-4 py-3 text-sm" style={{ background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)', color: '#ff2d55' }}>{error}</div>
        )}
        {notifResult && (
          <div className="rounded-lg px-4 py-3 text-sm flex items-center justify-between" style={{ background: 'rgba(48,209,88,0.1)', border: '1px solid rgba(48,209,88,0.3)', color: '#30d158' }}>
            <span>{notifResult}</span>
            <button onClick={() => setNotifResult(null)} className="text-xs font-bold px-3 py-1 rounded" style={{ border: '1px solid rgba(48,209,88,0.4)', color: '#30d158' }}>Dismiss</button>
          </div>
        )}

        {/* Pending Actions — approval queue (high-impact isolate/indefinite-block) */}
        <div className="p-5 rounded-lg" style={cardStyle}>
          <div className="flex items-center gap-3 mb-2">
            <Clock className="w-5 h-5" style={{ color: '#60a5fa' }} />
            <span className="text-sm font-bold uppercase" style={{ color: '#6b7280' }}>Pending Actions — Approval Queue ({pendingActions.length})</span>
          </div>
          <p className="text-xs mb-4" style={{ color: '#6b7280' }}>High-impact actions (host isolation, indefinite IP block) wait here for human approval. Low-impact notify/audit auto-execute and appear in history below.</p>
          <div className="flex gap-2 mb-4">
            <input type="text" value={pendingIncidentId} onChange={(e) => setPendingIncidentId(e.target.value)}
              placeholder="Filter by incident ID (empty = show global queue)..."
              className="flex-1 text-sm rounded px-3 py-2" style={inputStyle}
              onKeyDown={(e) => e.key === 'Enter' && fetchPendingActions()} />
            <button onClick={fetchPendingActions}
              className="text-xs font-bold px-4 py-2 rounded" style={{ border: '1px solid rgba(96,165,250,0.4)', color: '#60a5fa', background: 'rgba(96,165,250,0.08)' }}>
              Search
            </button>
          </div>
          {pendingActions.length === 0 && (
            <p className="text-sm" style={{ color: '#6b7280' }}>No pending actions — queue is clear.</p>
          )}
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {pendingActions.map((a: any) => {
              const sc = statusColors[a.status] || statusColors.PENDING;
              const incId = a.incident_id || pendingIncidentId.trim();
              return (
                <div key={a.action_id} className="flex items-center justify-between p-3 rounded transition-all" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(75,85,99,0.15)' }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(96,165,250,0.3)'; }} onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(75,85,99,0.15)'; }}>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-bold" style={{ color: '#d1d5db' }}>{a.name}</span>
                      <span className="text-xs px-2 py-0.5 rounded font-bold" style={{ color: sc.color, background: sc.bg }}>{a.status}</span>
                      {incId && <code className="text-xs" style={{ color: '#60a5fa' }}>{incId.slice(0, 8)}…</code>}
                    </div>
                    <code className="text-xs" style={{ color: '#6b7280' }}>{a.action_id}</code>
                    {a.params && Object.keys(a.params).length > 0 && (
                      <pre className="text-xs mt-1" style={{ color: '#6b7280' }}>{JSON.stringify(a.params, null, 1)}</pre>
                    )}
                  </div>
                  {a.status === 'PENDING' && (
                    <div className="flex gap-2 ml-3 shrink-0">
                      <button onClick={() => handleApprove(incId, a.action_id)} disabled={actingId === a.action_id} className="text-xs font-bold px-3 py-1.5 rounded disabled:opacity-40" style={{ border: '1px solid rgba(34,197,94,0.4)', color: '#22c55e', background: 'rgba(34,197,94,0.08)' }}>
                        {actingId === a.action_id ? 'Working...' : 'Approve'}
                      </button>
                      <button onClick={() => handleReject(incId, a.action_id)} disabled={actingId === a.action_id} className="text-xs font-bold px-3 py-1.5 rounded disabled:opacity-40" style={{ border: '1px solid rgba(255,45,85,0.4)', color: '#ff2d55', background: 'rgba(255,45,85,0.08)' }}>
                        Reject
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Endpoint Response — remote contain / recover via agent task-pull */}
        <div className="p-5 rounded-lg" style={cardStyle}>
          <div className="flex items-center gap-3 mb-2">
            <Shield className="w-5 h-5" style={{ color: '#60a5fa' }} />
            <span className="text-sm font-bold uppercase" style={{ color: '#6b7280' }}>Endpoint Response — Contain / Recover ({agentTasks.length})</span>
          </div>
          <p className="text-xs mb-4" style={{ color: '#6b7280' }}>
            Agents poll for these tasks every ~30s and report back. No EDR needed. Untargeted tasks go to any agent; set a hostname to pin one endpoint.
          </p>
          <div className="flex gap-2 mb-4 flex-wrap">
            <select value={taskAction} onChange={(e) => setTaskAction(e.target.value)} className="text-sm rounded px-3 py-2" style={inputStyle}>
              <option value="isolate">isolate (cut endpoint off)</option>
              <option value="unisolate">unisolate (recover)</option>
              <option value="block">block IP on endpoint</option>
              <option value="unblock">unblock IP on endpoint</option>
            </select>
            <input type="text" value={taskTarget} onChange={(e) => setTaskTarget(e.target.value)}
              placeholder="Target host or IP..." className="flex-1 text-sm rounded px-3 py-2 min-w-40" style={inputStyle}
              onKeyDown={(e) => e.key === 'Enter' && handleQueueTask()} />
            <input type="text" value={taskHost} onChange={(e) => setTaskHost(e.target.value)}
              placeholder="Hostname pin (optional)..." className="text-sm rounded px-3 py-2 w-48" style={inputStyle} />
            <button onClick={handleQueueTask} disabled={queueing}
              className="text-xs font-bold px-4 py-2 rounded disabled:opacity-40" style={{ border: '1px solid rgba(255,149,0,0.4)', color: '#ff9500', background: 'rgba(255,149,0,0.08)' }}>
              {queueing ? 'Queueing...' : 'Queue task'}
            </button>
          </div>
          {agentTasks.length === 0 ? (
            <p className="text-sm" style={{ color: '#6b7280' }}>No endpoint tasks queued.</p>
          ) : (
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {agentTasks.map((t: any) => {
                const sc = statusColors[t.status === 'DONE' ? 'EXECUTED' : t.status === 'FAILED' ? 'FAILED' : t.status === 'ACKED' ? 'APPROVED' : 'PENDING'] || statusColors.PENDING;
                return (
                  <div key={t.task_id} className="flex items-center justify-between p-3 rounded gap-2 flex-wrap" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(75,85,99,0.15)' }}>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-bold" style={{ color: '#d1d5db' }}>agent:{t.action}</span>
                        <span className="text-xs px-2 py-0.5 rounded font-bold" style={{ color: sc.color, background: sc.bg }}>{t.status}</span>
                        <code className="text-xs" style={{ color: '#60a5fa' }}>{t.target}</code>
                        {t.hostname && <code className="text-xs" style={{ color: '#6b7280' }}>@{t.hostname}</code>}
                      </div>
                      <div className="text-xs mt-1" style={{ color: '#6b7280' }}>
                        {t.task_id.slice(0, 8)}… · by {t.requested_by || 'admin'} · {t.created_at ? new Date(t.created_at).toLocaleString() : ''}
                        {t.result?.detail && <span style={{ color: '#9ca3af' }}> · {t.result.detail}</span>}
                      </div>
                    </div>
                    {(t.action === 'isolate' || t.action === 'block') && t.status === 'DONE' && (
                      <button
                        onClick={() => handleRecover(t.action === 'isolate' ? 'unisolate' : 'unblock', t.action === 'isolate' ? (t.hostname || t.target) : t.target)}
                        className="text-xs font-bold px-3 py-1.5 rounded shrink-0" style={{ border: '1px solid rgba(34,197,94,0.4)', color: '#22c55e', background: 'rgba(34,197,94,0.08)' }}>
                        {t.action === 'isolate' ? 'Recover host' : 'Remove block'}
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Execution History */}        <div className="p-5 rounded-lg" style={cardStyle}>
          <div className="flex items-center gap-3 mb-4">
            <History className="w-5 h-5" style={{ color: '#60a5fa' }} />
            <span className="text-sm font-bold uppercase" style={{ color: '#6b7280' }}>Execution History ({history.length})</span>
          </div>
          {loading && history.length === 0 ? (
            <div className="flex justify-center py-12"><div className="w-8 h-8 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: '#333', borderTopColor: '#60a5fa' }} /></div>
          ) : history.length === 0 ? (
            <p className="text-sm text-center py-8" style={{ color: '#6b7280' }}>No SOAR actions executed yet.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr style={{ borderBottom: '1px solid rgba(75,85,99,0.2)' }}>
                  <th className="text-left py-2 px-3 text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Timestamp</th>
                  <th className="text-left py-2 px-3 text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Incident</th>
                  <th className="text-left py-2 px-3 text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Action</th>
                  <th className="text-left py-2 px-3 text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Status</th>
                  <th className="text-left py-2 px-3 text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Actor</th>
                </tr></thead>
                <tbody>
                  {history.map((h, i) => {
                    const sc = statusColors[h.status || 'PENDING'] || statusColors.PENDING;
                    return (
                      <tr key={h.action_id || i} style={{ borderBottom: '1px solid rgba(75,85,99,0.1)' }}>
                        <td className="py-2 px-3 font-mono text-xs" style={{ color: '#6b7280' }}>{h.timestamp ? new Date(h.timestamp).toLocaleString() : '-'}</td>
                        <td className="py-2 px-3"><code className="text-xs" style={{ color: '#d1d5db' }}>{h.incident_id || '-'}</code></td>
                        <td className="py-2 px-3 text-sm" style={{ color: '#d1d5db' }}>{h.action || (h as any).name || h.action_id || '-'}</td>
                        <td className="py-2 px-3"><span className="text-xs px-2 py-0.5 rounded font-bold" style={{ color: sc.color, background: sc.bg }}>{h.status || 'PENDING'}</span></td>
                        <td className="py-2 px-3 text-xs font-mono" style={{ color: '#6b7280' }}>{(h as any).actor || (h as any).approved_by || 'system'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Correlation Rules (moved from Dashboard) */}
        <div className="p-5 rounded-lg" style={cardStyle}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Shield className="w-5 h-5" style={{ color: '#60a5fa' }} />
              <span className="text-sm font-bold uppercase" style={{ color: '#6b7280' }}>Correlation Rules</span>
            </div>
            <button onClick={fetchRules} className="text-xs px-2 py-1 rounded" style={{ border: '1px solid #333', color: '#9ca3af' }}>Refresh</button>
          </div>
          <div className="grid gap-1">
            {rules.map((rule) => (
              <div key={rule.id} className="flex items-center justify-between p-2 rounded transition-all" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(75,85,99,0.15)' }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(96,165,250,0.3)'; }} onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(75,85,99,0.15)'; }}>
                <div className="flex-1 min-w-0 mr-2">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold" style={{ color: '#d1d5db' }}>{rule.name}</span>
                    {rule.risk_score >= 70 && (<span className="text-xs px-1 py-0.5 rounded" style={{ background: 'rgba(239,68,68,0.1)', color: '#ef4444' }}>{rule.risk_score}</span>)}
                  </div>
                  <p className="text-xs mt-0.5 truncate" style={{ color: '#6b7280' }}>{rule.description || ''}{rule.threshold > 1 && ` | threshold: ${rule.threshold} / ${rule.window_seconds}s`}</p>
                </div>
                <button disabled={togglingRule === rule.id} onClick={() => handleToggleRule(rule.id)}
                  className="text-xs font-bold px-2.5 py-1 rounded uppercase tracking-wider disabled:opacity-40"
                  style={{ background: rule.enabled ? 'rgba(34,197,94,0.15)' : 'rgba(75,85,99,0.15)', color: rule.enabled ? '#22c55e' : '#6b7280', border: '1px solid ' + (rule.enabled ? 'rgba(34,197,94,0.3)' : 'rgba(75,85,99,0.3)'), minWidth: '48px' }}>
                  {rule.enabled ? 'ON' : 'OFF'}
                </button>
              </div>
            ))}
            {rules.length === 0 && !rulesLoading && (<p className="text-sm py-4 text-center" style={{ color: '#6b7280' }}>No correlation rules loaded</p>)}
          </div>
        </div>

        {/* Notification Channel Config */}
        <div className="p-5 rounded-lg" style={cardStyle}>
          <div className="flex items-center gap-3 mb-4">
            <Bell className="w-5 h-5" style={{ color: '#60a5fa' }} />
            <span className="text-sm font-bold uppercase" style={{ color: '#6b7280' }}>Notification Channel Configuration</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-bold mb-2" style={{ color: '#6b7280' }}>Channel</label>
              <select value={notifChannel} onChange={(e) => setNotifChannel(e.target.value)} className="w-full px-3 py-2 rounded text-sm" style={inputStyle}>
                <option value="SIEM">SIEM Audit Log</option>
                <option value="TELEGRAM">Telegram</option>
                <option value="EMAIL">Email (SMTP — backend supported)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-bold mb-2" style={{ color: '#6b7280' }}>Enabled</label>
              <button onClick={() => setNotifEnabled(!notifEnabled)} className="text-xs font-bold px-3 py-1.5 rounded uppercase tracking-wider"
                style={{ background: notifEnabled ? 'rgba(34,197,94,0.15)' : 'rgba(75,85,99,0.15)', color: notifEnabled ? '#22c55e' : '#6b7280', border: '1px solid ' + (notifEnabled ? 'rgba(34,197,94,0.3)' : 'rgba(75,85,99,0.3)' ) }}>
                {notifEnabled ? 'ON' : 'OFF'}
              </button>
            </div>
          </div>
          <div className="mt-4">
            <label className="block text-xs font-bold mb-2" style={{ color: '#6b7280' }}>Channel Config (JSON)</label>
            <textarea value={notifConfig} onChange={(e) => setNotifConfig(e.target.value)} className="w-full h-24 text-xs px-3 py-2 rounded" style={inputStyle} spellCheck={false} />
          </div>
          <button onClick={handleRegisterNotification} disabled={registering} className="mt-3 text-xs font-bold px-4 py-2 rounded disabled:opacity-40"
            style={{ border: '1px solid rgba(96,165,250,0.4)', color: '#60a5fa', background: 'rgba(96,165,250,0.08)' }}>
            {registering ? 'Registering...' : 'Register Channel'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default SOAR;
