import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, ArrowLeft, ShieldAlert, Save, Zap, PlusCircle, Globe, Bot } from 'lucide-react';
import { apiService } from '../services/api';

// ── One-click hunt packs (raw-log DSL via /api/logs/hunt, or incident filters) ──
type HuntPack =
  | { id: string; name: string; technique: string; kind: 'logs'; dsl: any }
  | { id: string; name: string; technique: string; kind: 'incidents'; attack_type: string };

const HUNT_PACKS: HuntPack[] = [
  { id: 'kerberoast', name: 'Kerberoasting (4769 burst)', technique: 'T1558.003', kind: 'logs',
    dsl: { query: { match: { message: '4769' } }, size: 100, sort: [{ timestamp: { order: 'desc' } }] } },
  { id: 'asrep', name: 'AS-REP Roasting (4771)', technique: 'T1558.002', kind: 'logs',
    dsl: { query: { match: { message: '4771' } }, size: 100, sort: [{ timestamp: { order: 'desc' } }] } },
  { id: 'rdp-lateral', name: 'RDP lateral movement (4778/4779)', technique: 'T1021.001', kind: 'logs',
    dsl: { query: { multi_match: { query: '4778 4779', fields: ['message'] } }, size: 100, sort: [{ timestamp: { order: 'desc' } }] } },
  { id: 'kerb-incidents', name: 'Kerberos incidents', technique: 'T1558', kind: 'incidents', attack_type: 'kerberoasting' },
  { id: 'lateral-incidents', name: 'Lateral movement incidents', technique: 'T1021', kind: 'incidents', attack_type: 'lateral_movement' },
  { id: 'dns-incidents', name: 'DNS tunneling incidents', technique: 'T1071.004', kind: 'incidents', attack_type: 'dns_tunneling' },
  { id: 'failed-logons', name: 'Failed logons', technique: 'T1110', kind: 'logs',
    dsl: { query: { multi_match: { query: 'failed', fields: ['message'] } }, size: 100, sort: [{ timestamp: { order: 'desc' } }] } },
  { id: 'critical', name: 'Critical severity logs', technique: '—', kind: 'logs',
    dsl: { query: { term: { severity: 'CRITICAL' } }, size: 100, sort: [{ timestamp: { order: 'desc' } }] } },
];

const Hunt: React.FC = () => {
  const navigate = useNavigate();
  const [incidentFilters, setIncidentFilters] = useState({
    search: '',
    status: '',
    risk_score_min: '',
    risk_score_max: '',
    host: '',
    attack_type: '',
  });
  const [incidentHuntResults, setIncidentHuntResults] = useState<any>(null);
  const [incidentHuntLoading, setIncidentHuntLoading] = useState(false);
  const [savedHunts, setSavedHunts] = useState<any[]>(() => {
    return JSON.parse(localStorage.getItem('chael-saved-hunts') || '[]');
  });
  const [huntName, setHuntName] = useState('');
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [logHuntResults, setLogHuntResults] = useState<any>(null);
  const [logHuntLoading, setLogHuntLoading] = useState(false);
  const [logHuntError, setLogHuntError] = useState<string | null>(null);
  const [activePack, setActivePack] = useState<string | null>(null);
  const [createMsg, setCreateMsg] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  // External IOC confirmation (live: ip-api/NVD free + keyed VT/AbuseIPDB/Shodan/OTX/GreyNoise)
  const [iocType, setIocType] = useState('ip');
  const [iocValue, setIocValue] = useState('');
  const [iocResult, setIocResult] = useState<any>(null);
  const [iocLoading, setIocLoading] = useState(false);
  const [iocError, setIocError] = useState<string | null>(null);
  const [srcStatus, setSrcStatus] = useState<any>(null);
  // AI hunt assistant (hypothesis → plan + DSL + external-confirmation steps)
  const [huntHypo, setHuntHypo] = useState('');
  const [huntAssist, setHuntAssist] = useState<any>(null);
  const [huntAssistLoading, setHuntAssistLoading] = useState(false);
  const [huntAssistError, setHuntAssistError] = useState<string | null>(null);

  useEffect(() => {
    apiService.enrichStatus().then((r) => setSrcStatus(r.data)).catch(() => setSrcStatus(null));
  }, []);

  const runIocLookup = async () => {
    const v = iocValue.trim();
    if (!v || iocLoading) return;
    setIocLoading(true);
    setIocError(null);
    setIocResult(null);
    try {
      const res = await apiService.enrichIoc(iocType, v);
      setIocResult(res.data);
    } catch (err: any) {
      setIocError(err?.response?.data?.detail || err?.message || 'External lookup failed');
    } finally {
      setIocLoading(false);
    }
  };

  const runHuntAssist = async () => {
    const h = huntHypo.trim();
    if (!h || huntAssistLoading) return;
    setHuntAssistLoading(true);
    setHuntAssistError(null);
    setHuntAssist(null);
    try {
      const res = await apiService.aiHuntAssist(h, { external_intel: iocResult || undefined });
      setHuntAssist(res.data);
    } catch (err: any) {
      setHuntAssistError(err?.response?.data?.detail || err?.message || 'Hunt assist failed');
    } finally {
      setHuntAssistLoading(false);
    }
  };

  const runAssistDsl = async (dsl: any) => {
    if (!dsl || logHuntLoading) return;
    setLogHuntLoading(true);
    setLogHuntError(null);
    setLogHuntResults(null);
    try {
      const response = await apiService.advancedHunt(dsl, 100);
      setLogHuntResults({ ...response.data, pack: { name: 'AI hunt assist' } as any });
    } catch (error: any) {
      setLogHuntError(error?.response?.data?.detail || error?.message || 'Log hunt failed');
    } finally {
      setLogHuntLoading(false);
    }
  };

  const executeLogPack = async (pack: Extract<HuntPack, { kind: 'logs' }>) => {
    setActivePack(pack.id);
    setLogHuntLoading(true);
    setLogHuntError(null);
    setLogHuntResults(null);
    setCreateMsg(null);
    try {
      const response = await apiService.advancedHunt(pack.dsl, 100);
      setLogHuntResults({ ...response.data, pack });
    } catch (error: any) {
      setLogHuntError(error?.response?.data?.detail || error?.message || 'Log hunt failed');
    } finally {
      setLogHuntLoading(false);
    }
  };

  const executeIncidentPack = async (pack: Extract<HuntPack, { kind: 'incidents' }>) => {
    setActivePack(pack.id);
    const next = { search: '', status: '', risk_score_min: '', risk_score_max: '', host: '', attack_type: pack.attack_type };
    setIncidentFilters(next);
    setIncidentHuntLoading(true);
    try {
      const response = await apiService.huntIncidents({ attack_type: pack.attack_type, limit: 100 });
      setIncidentHuntResults(response.data);
    } catch (error) {
      console.error('Incident hunt failed:', error);
      setIncidentHuntResults(null);
    } finally {
      setIncidentHuntLoading(false);
    }
  };

  const runPack = (pack: HuntPack) => {
    if (pack.kind === 'logs') return executeLogPack(pack);
    return executeIncidentPack(pack);
  };

  const createIncidentFromHits = async () => {
    const hits = logHuntResults?.hits || [];
    const pack = logHuntResults?.pack;
    if (!hits.length || creating) return;
    setCreating(true);
    setCreateMsg(null);
    try {
      const hosts = [...new Set(hits.map((h: any) => h.host).filter(Boolean))].slice(0, 5);
      const res = await apiService.createIncident({
        timestamp: new Date().toISOString(),
        risk_score: 70,
        source_logs: hits.slice(0, 10),
        status: 'OPEN',
        description: `Threat hunt hit: ${pack?.name || 'manual hunt'} (${hits.length} matching logs${hosts.length ? ` on ${hosts.join(', ')}` : ''})`,
        artifacts: { hunt_pack: pack?.id || 'manual', technique: pack?.technique || '', host: hosts[0] || '', attack_type: pack?.id || 'threat_hunt' },
      } as any);
      setCreateMsg(`Incident created: ${(res.data as any)?.incident_id || 'OK'} — open the Incidents page to triage.`);
    } catch (error: any) {
      setCreateMsg(`Create failed: ${error?.response?.data?.detail || error?.message || 'unknown error'}`);
    } finally {
      setCreating(false);
    }
  };

  const executeIncidentHunt = async () => {
    setIncidentHuntLoading(true);
    try {
      const params: any = {};
      if (incidentFilters.search) params.search = incidentFilters.search;
      if (incidentFilters.status) params.status = incidentFilters.status;
      if (incidentFilters.risk_score_min) params.risk_score_min = parseInt(incidentFilters.risk_score_min);
      if (incidentFilters.risk_score_max) params.risk_score_max = parseInt(incidentFilters.risk_score_max);
      if (incidentFilters.host) params.host = incidentFilters.host;
      if (incidentFilters.attack_type) params.attack_type = incidentFilters.attack_type;
      params.limit = 100;
      const response = await apiService.huntIncidents(params);
      setIncidentHuntResults(response.data);
    } catch (error) {
      console.error('Incident hunt failed:', error);
      setIncidentHuntResults(null);
    } finally {
      setIncidentHuntLoading(false);
    }
  };

  const handleSaveHunt = () => {
    if (!huntName.trim()) return;
    const saved = JSON.parse(localStorage.getItem('chael-saved-hunts') || '[]');
    saved.push({
      name: huntName,
      filters: { ...incidentFilters },
      timestamp: new Date().toISOString(),
    });
    localStorage.setItem('chael-saved-hunts', JSON.stringify(saved));
    setSavedHunts(saved);
    setHuntName('');
    setShowSaveDialog(false);
  };

  const handleLoadHunt = (hunt: any) => {
    setIncidentFilters(hunt.filters || { search: '', status: '', risk_score_min: '', risk_score_max: '', host: '', attack_type: '' });
  };

  const handleDeleteSavedHunt = (idx: number) => {
    const saved = JSON.parse(localStorage.getItem('chael-saved-hunts') || '[]');
    saved.splice(idx, 1);
    localStorage.setItem('chael-saved-hunts', JSON.stringify(saved));
    setSavedHunts(saved);
  };

  return (
    <div>
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Navigation */}
        <div className="flex items-center justify-between">
          <button
            onClick={() => navigate('/dashboard')}
            className="flex items-center gap-2 text-xs font-bold tracking-widest uppercase hover:text-blue-400 transition-all" style={{ color: '#6b7280' }}
          >
            <ArrowLeft className="w-4 h-4" /> Back to Base
          </button>
          <div className="flex items-center gap-4">
            {savedHunts.length > 0 && (
              <div className="relative group">
                <button className="flex items-center gap-2 px-3 py-1 rounded text-[10px] font-bold tracking-widest transition-all" style={{ border: '1px solid rgba(75,85,99,0.5)', color: '#6b7280' }}>
                  <Save className="w-3 h-3" /> Saved Hunts ({savedHunts.length})
                </button>
                <div className="absolute right-0 top-full mt-1 w-64 rounded-lg z-50 hidden group-hover:block" style={{ background: '#0a0a0a', border: '1px solid rgba(75,85,99,0.5)' }}>
                  <div className="p-2 space-y-1">
                    {savedHunts.map((h, i) => (
                      <div key={i} className="flex items-center justify-between p-2 rounded hover:bg-white/5 text-xs">
                        <button onClick={() => handleLoadHunt(h)} className="text-left flex-1">
                          <span style={{ color: '#d1d5db' }} className="block">{h.name}</span>
                          <span className="text-[9px]" style={{ color: '#6b7280' }}>{new Date(h.timestamp).toLocaleDateString()}</span>
                        </button>
                        <button onClick={() => handleDeleteSavedHunt(i)} className="text-red-500 hover:text-red-400 ml-2">Delete</button>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-lg" style={{ background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.2)' }}>
              <ShieldAlert className="w-8 h-8" style={{ color: '#f59e0b' }} />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-[0.2em] uppercase" style={{ color: '#d1d5db' }}>Threat Hunting</h1>
              <p className="text-xs mt-1 uppercase tracking-widest" style={{ color: '#6b7280' }}>
                Search and filter security incidents for proactive threat detection
              </p>
            </div>
          </div>
        </div>

        {/* Hunt Packs — one-click proactive hunts */}
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: '4px', padding: '20px' }}>
          <div className="flex items-center gap-3 mb-4">
            <Zap className="w-5 h-5" style={{ color: '#f59e0b' }} />
            <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Hunt Packs (one-click)</div>
          </div>
          <div className="flex flex-wrap gap-2">
            {HUNT_PACKS.map((pack) => (
              <button
                key={pack.id}
                onClick={() => runPack(pack)}
                disabled={logHuntLoading || incidentHuntLoading}
                className="text-[11px] px-3 py-1.5 rounded font-bold disabled:opacity-40 flex items-center gap-1.5"
                style={activePack === pack.id
                  ? { border: '1px solid #f59e0b', color: '#f59e0b', background: 'rgba(245,158,11,0.15)' }
                  : { border: '1px solid #333', color: '#9ca3af', background: 'transparent' }}
              >
                {pack.name}
                <span className="font-mono font-normal opacity-60">{pack.technique}</span>
              </button>
            ))}
          </div>
        </div>

        {/* External IOC confirmation — live lookups (free ip-api/NVD + keyed sources) */}
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(96,165,250,0.25)', borderRadius: '4px', padding: '20px' }}>
          <div className="flex items-center gap-3 mb-2">
            <Globe className="w-5 h-5" style={{ color: '#60a5fa' }} />
            <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>External IOC confirmation (live)</div>
          </div>
          <p className="text-xs mb-4" style={{ color: '#6b7280' }}>
            Confirm any IP / domain / hash / CVE against live external sources before containment.
            Free sources (ip-api geo, Shodan InternetDB exposure, NVD + Shodan CVEDB vuln detail) always work; keyed sources light up when their API keys are in .env.
            {srcStatus && (
              <span className="font-mono"> Live now: {(srcStatus.sources_live || []).join(', ') || 'none'}.</span>
            )}
          </p>
          <div className="flex gap-2 flex-wrap">
            <select value={iocType} onChange={(e) => setIocType(e.target.value)} className="text-xs rounded px-2 py-2" style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}>
              <option value="ip">IP</option>
              <option value="domain">Domain</option>
              <option value="hash">Hash</option>
              <option value="cve">CVE</option>
            </select>
            <input value={iocValue} onChange={(e) => setIocValue(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') runIocLookup(); }} placeholder={iocType === 'ip' ? 'e.g. 8.8.8.8' : iocType === 'cve' ? 'e.g. CVE-2024-1234' : 'paste IOC…'} className="flex-1 min-w-[220px] text-xs rounded px-3 py-2 font-mono" style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }} />
            <button onClick={runIocLookup} disabled={!iocValue.trim() || iocLoading} className="text-[11px] px-4 py-2 rounded font-bold disabled:opacity-40" style={{ border: '1px solid #60a5fa', color: '#60a5fa', background: 'rgba(96,165,250,0.1)' }}>
              {iocLoading ? 'Checking…' : 'Check live'}
            </button>
          </div>
          {iocError && <p className="text-xs mt-3" style={{ color: '#ff2d55' }}>{iocError}</p>}
          {iocResult && !iocResult.error && (
            <div className="mt-4 p-4 rounded text-xs space-y-3" style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(75,85,99,0.3)' }}>
              <div className="flex items-center justify-between flex-wrap gap-2">
                <span className="font-mono font-bold" style={{ color: '#d1d5db' }}>{iocResult.type}: {iocResult.value}</span>
                <span className="font-mono" style={{ color: '#6b7280' }}>sources: {(iocResult.sources_queried || []).join(', ') || 'none'}</span>
              </div>
              {iocResult.verdict_hint && <p style={{ color: '#f59e0b' }}>{iocResult.verdict_hint}</p>}
              {iocResult.results && Object.keys(iocResult.results).length > 0 ? (
                <pre className="whitespace-pre-wrap break-all font-mono" style={{ color: '#9ca3af' }}>{JSON.stringify(iocResult.results, null, 2).slice(0, 2500)}</pre>
              ) : (
                <p style={{ color: '#6b7280' }}>No reputation hits — treat as unverified; use reference links below to confirm manually.</p>
              )}
              {iocResult.references && (
                <div className="flex gap-3 flex-wrap">
                  {Object.entries(iocResult.references).map(([k, url]: [string, any]) => (
                    <a key={k} href={url} target="_blank" rel="noopener noreferrer" className="hover:underline font-bold uppercase" style={{ color: '#60a5fa', fontSize: '10px' }}>{k} ↗</a>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* AI hunt assistant — hypothesis → plan + DSL + external-confirmation steps */}
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(34,197,94,0.25)', borderRadius: '4px', padding: '20px' }}>
          <div className="flex items-center gap-3 mb-2">
            <Bot className="w-5 h-5" style={{ color: '#22c55e' }} />
            <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>AI hunt assistant (live)</div>
          </div>
          <p className="text-xs mb-4" style={{ color: '#6b7280' }}>
            Describe what you're hunting ("possible Kerberoasting on DC01", "DNS tunneling from host X"). Chael AI builds a MITRE-mapped hunt plan + log query + external-confirmation steps, grounded in live SIEM state.
          </p>
          <div className="flex gap-2">
            <input value={huntHypo} onChange={(e) => setHuntHypo(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') runHuntAssist(); }} placeholder="e.g. hunt Kerberoasting burst on the domain…" className="flex-1 text-xs rounded px-3 py-2" style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }} />
            <button onClick={runHuntAssist} disabled={!huntHypo.trim() || huntAssistLoading} className="text-[11px] px-4 py-2 rounded font-bold disabled:opacity-40" style={{ border: '1px solid #22c55e', color: '#22c55e', background: 'rgba(34,197,94,0.1)' }}>
              {huntAssistLoading ? 'Planning…' : 'Plan hunt'}
            </button>
          </div>
          {huntAssistError && <p className="text-xs mt-3" style={{ color: '#ff2d55' }}>{huntAssistError}</p>}
          {huntAssist && (
            <div className="mt-4 p-4 rounded text-xs space-y-3" style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(75,85,99,0.3)', color: '#d1d5db' }}>
              <div><span className="font-bold uppercase" style={{ color: '#22c55e' }}>Hypothesis: </span>{huntAssist.hypothesis}</div>
              {(huntAssist.mitre || []).length > 0 && <div><span className="font-bold uppercase" style={{ color: '#6b7280' }}>MITRE: </span><span className="font-mono">{huntAssist.mitre.join(', ')}</span></div>}
              {huntAssist.explanation && <p className="whitespace-pre-wrap" style={{ color: '#9ca3af' }}>{typeof huntAssist.explanation === 'string' ? huntAssist.explanation.slice(0, 1500) : JSON.stringify(huntAssist.explanation).slice(0, 1500)}</p>}
              {(huntAssist.hunt_steps || []).length > 0 && (
                <div>{huntAssist.hunt_steps.map((s: string, i: number) => <p key={i} className="mt-1">• {s}</p>)}</div>
              )}
              {(huntAssist.external_confirmation || []).length > 0 && (
                <div className="pt-2" style={{ borderTop: '1px solid rgba(75,85,99,0.2)' }}>
                  <span className="font-bold uppercase" style={{ color: '#60a5fa' }}>Confirm externally:</span>
                  {huntAssist.external_confirmation.map((s: string, i: number) => <p key={i} className="mt-1">• {s}</p>)}
                </div>
              )}
              <div className="flex gap-2 flex-wrap pt-1">
                {huntAssist.dsl && (
                  <button onClick={() => runAssistDsl(huntAssist.dsl)} disabled={logHuntLoading} className="text-[11px] px-3 py-1.5 rounded font-bold disabled:opacity-40" style={{ border: '1px solid rgba(245,158,11,0.4)', color: '#f59e0b', background: 'rgba(245,158,11,0.08)' }}>
                    {logHuntLoading ? 'Hunting…' : 'Run AI query on logs'}
                  </button>
                )}
                <span className="font-mono self-center" style={{ color: '#6b7280' }}>engine: {huntAssist.engine || 'unknown'} · human approval required</span>
              </div>
            </div>
          )}
        </div>

        {/* Log Hunt Results (raw-log packs + Copilot queries) */}
        {(logHuntLoading || logHuntError || logHuntResults) && (
          <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: '4px', overflow: 'hidden' }}>
            <div className="px-6 py-4 flex justify-between items-center flex-wrap gap-2" style={{ borderBottom: '1px solid rgba(75,85,99,0.4)', background: 'rgba(255,255,255,0.05)' }}>
              <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>
                Log Hunt: {logHuntResults?.pack?.name || activePack} ({logHuntResults?.total ?? 0} hits{logHuntResults?.took != null ? ` · ${logHuntResults.took}ms` : ''})
              </div>
              <div className="flex items-center gap-2">
                {createMsg && <span className="text-[10px]" style={{ color: '#22c55e' }}>{createMsg}</span>}
                <button
                  onClick={createIncidentFromHits}
                  disabled={!logHuntResults?.hits?.length || creating}
                  className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest disabled:opacity-30"
                  style={{ border: '1px solid rgba(34,197,94,0.4)', color: '#22c55e', background: 'rgba(34,197,94,0.08)', borderRadius: '4px', padding: '6px 12px' }}
                >
                  <PlusCircle className="w-3 h-3" /> {creating ? 'Creating…' : 'Create Incident'}
                </button>
              </div>
            </div>
            <div className="max-h-96 overflow-y-auto custom-scrollbar">
              {logHuntLoading ? (
                <div className="px-6 py-10 text-center text-xs animate-pulse" style={{ color: '#6b7280' }}>Hunting logs…</div>
              ) : logHuntError ? (
                <div className="px-6 py-10 text-center text-xs" style={{ color: '#ff2d55' }}>{logHuntError}</div>
              ) : (logHuntResults?.hits || []).length === 0 ? (
                <div className="px-6 py-10 text-center text-xs" style={{ color: '#6b7280' }}>No matching logs — no evidence of this technique in the retention window.</div>
              ) : (
                (logHuntResults.hits as any[]).slice(0, 50).map((hit: any, i: number) => (
                  <div key={i} className="px-6 py-3 text-xs" style={{ borderTop: i > 0 ? '1px solid rgba(75,85,99,0.1)' : undefined }}>
                    <span className="font-mono" style={{ color: '#6b7280' }}>{hit.timestamp ? new Date(hit.timestamp).toLocaleString() : ''}</span>
                    {' '}<span className="font-bold" style={{ color: '#d1d5db' }}>{hit.host || ''}</span>
                    {' '}<span className="font-mono" style={{ color: '#f59e0b' }}>{hit.severity || ''}</span>
                    <div className="mt-1 font-mono break-all" style={{ color: '#9ca3af' }}>{(hit.message || '').slice(0, 300)}</div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* Search & Filter Bar */}
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: '4px', padding: '24px' }} className="space-y-6">
          <div className="flex items-center gap-3 mb-4">
            <ShieldAlert className="w-5 h-5" style={{ color: '#f59e0b' }} />
            <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Incident Search Filters</div>
          </div>

          <form onSubmit={(e) => { e.preventDefault(); executeIncidentHunt(); }} className="space-y-4">
            <div className="relative">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5" style={{ color: '#6b7280' }} />
              <input
                type="text"
                placeholder="Search incident descriptions or IDs..."
                className="pl-12 w-full h-12 text-sm rounded px-2 py-1"
                style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
                value={incidentFilters.search}
                onChange={(e) => setIncidentFilters({...incidentFilters, search: e.target.value})}
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <div className="text-[10px] uppercase font-bold px-1" style={{ color: '#6b7280' }}>Status</div>
                <select
                  className="text-xs rounded px-2 py-1 w-full"
                  style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
                  value={incidentFilters.status}
                  onChange={(e) => setIncidentFilters({...incidentFilters, status: e.target.value})}
                >
                  <option value="">All Statuses</option>
                  <option value="OPEN">Open</option>
                  <option value="INVESTIGATING">Investigating</option>
                  <option value="RESOLVED">Resolved</option>
                  <option value="FALSE_POSITIVE">False Positive</option>
                </select>
              </div>
              <div className="space-y-2">
                <div className="text-[10px] uppercase font-bold px-1" style={{ color: '#6b7280' }}>Min Risk Score</div>
                <input
                  type="number"
                  min="0"
                  max="100"
                  placeholder="0"
                  className="text-xs rounded px-2 py-1 w-full"
                  style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
                  value={incidentFilters.risk_score_min}
                  onChange={(e) => setIncidentFilters({...incidentFilters, risk_score_min: e.target.value})}
                />
              </div>
              <div className="space-y-2">
                <div className="text-[10px] uppercase font-bold px-1" style={{ color: '#6b7280' }}>Max Risk Score</div>
                <input
                  type="number"
                  min="0"
                  max="100"
                  placeholder="100"
                  className="text-xs rounded px-2 py-1 w-full"
                  style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
                  value={incidentFilters.risk_score_max}
                  onChange={(e) => setIncidentFilters({...incidentFilters, risk_score_max: e.target.value})}
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <div className="text-[10px] uppercase font-bold px-1" style={{ color: '#6b7280' }}>Host</div>
                <input
                  type="text"
                  placeholder="Target hostname..."
                  className="text-xs rounded px-2 py-1 w-full"
                  style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
                  value={incidentFilters.host}
                  onChange={(e) => setIncidentFilters({...incidentFilters, host: e.target.value})}
                />
              </div>
              <div className="space-y-2">
                <div className="text-[10px] uppercase font-bold px-1" style={{ color: '#6b7280' }}>Attack Type</div>
                <input
                  type="text"
                  placeholder="e.g., brute_force, kerberoasting, lateral_movement..."
                  className="text-xs rounded px-2 py-1 w-full"
                  style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
                  value={incidentFilters.attack_type}
                  onChange={(e) => setIncidentFilters({...incidentFilters, attack_type: e.target.value})}
                />
              </div>
            </div>

            <div className="flex gap-4">
              <button type="submit" className="text-xs px-3 py-1.5 rounded flex items-center gap-2" style={{ border: '1px solid #f59e0b', color: '#f59e0b', background: 'rgba(245,158,11,0.1)' }}>
                <ShieldAlert className="w-4 h-4" /> Hunt Incidents
              </button>
              <button
                type="button"
                onClick={() => {
                  setIncidentFilters({ search: '', status: '', risk_score_min: '', risk_score_max: '', host: '', attack_type: '' });
                  setIncidentHuntResults(null);
                }}
                className="text-[10px] uppercase font-bold px-4 py-2 transition-all" style={{ color: '#6b7280' }}
              >
                Reset Filters
              </button>
            </div>
          </form>

          {incidentHuntResults && (
            <div style={{ borderTop: '1px solid rgba(75,85,99,0.3)' }} className="pt-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '12px' }}>
                  <div className="text-xs font-bold uppercase mb-1" style={{ color: '#6b7280' }}>Query Time</div>
                  <div className="font-mono" style={{ color: '#f59e0b' }}>{incidentHuntResults.took}ms</div>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '12px' }}>
                  <div className="text-xs font-bold uppercase mb-1" style={{ color: '#6b7280' }}>Total Incidents</div>
                  <div className="font-mono" style={{ color: '#22c55e' }}>{incidentHuntResults.total}</div>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '12px' }}>
                  <div className="text-xs font-bold uppercase mb-1" style={{ color: '#6b7280' }}>Returned</div>
                  <div className="font-mono" style={{ color: '#d1d5db' }}>{incidentHuntResults.hits?.length || 0}</div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Results Table */}
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: '4px', overflow: 'hidden' }}>
          <div className="px-6 py-4 flex justify-between items-center" style={{ borderBottom: '1px solid rgba(75,85,99,0.4)', background: 'rgba(255,255,255,0.05)' }}>
            <div className="flex items-center gap-3">
              <ShieldAlert className="w-4 h-4" style={{ color: '#f59e0b' }} />
              <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>
                Incident Results ({incidentHuntResults?.total || 0})
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowSaveDialog(true)}
                disabled={!incidentHuntResults?.total}
                className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest transition-all disabled:opacity-30" style={{ color: '#6b7280' }}
              >
                <Save className="w-3 h-3" /> Save Hunt
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-black/40" style={{ borderBottom: '1px solid rgba(75,85,99,0.2)' }}>
                  <th className="px-6 py-4 text-[10px] uppercase tracking-widest font-bold" style={{ color: '#6b7280' }}>Incident ID</th>
                  <th className="px-6 py-4 text-[10px] uppercase tracking-widest font-bold" style={{ color: '#6b7280' }}>Timestamp</th>
                  <th className="px-6 py-4 text-[10px] uppercase tracking-widest font-bold" style={{ color: '#6b7280' }}>Risk Score</th>
                  <th className="px-6 py-4 text-[10px] uppercase tracking-widest font-bold" style={{ color: '#6b7280' }}>Status</th>
                  <th className="px-6 py-4 text-[10px] uppercase tracking-widest font-bold" style={{ color: '#6b7280' }}>Description</th>
                  <th className="px-6 py-4 text-[10px] uppercase tracking-widest font-bold" style={{ color: '#6b7280' }}>Host</th>
                  <th className="px-6 py-4 text-[10px] uppercase tracking-widest font-bold" style={{ color: '#6b7280' }}>Attack Type</th>
                </tr>
              </thead>
              <tbody>
                {incidentHuntLoading ? (
                  Array(5).fill(0).map((_, i) => (
                    <tr key={i} className="animate-pulse">
                      <td colSpan={7} className="px-6 py-4"><div className="h-4 bg-white/5 rounded w-full" /></td>
                    </tr>
                  ))
                ) : !incidentHuntResults || incidentHuntResults.hits?.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-6 py-20 text-center">
                      <ShieldAlert className="w-12 h-12 mx-auto mb-4 opacity-10" />
                      <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>No incidents match your search criteria</div>
                      <button
                        onClick={() => { executeIncidentHunt(); }}
                        className="mt-4 text-xs px-4 py-2 rounded inline-flex items-center gap-2"
                        style={{ border: '1px solid #f59e0b', color: '#f59e0b', background: 'rgba(245,158,11,0.1)' }}
                      >
                        <Search className="w-3 h-3" /> Run Hunt
                      </button>
                    </td>
                  </tr>
                ) : (
                  incidentHuntResults.hits.map((inc: any, i: number) => {
                    const artifacts = inc.artifacts || {};
                    const host = artifacts.host || artifacts.target_host || '-';
                    const attackType = artifacts.attack_type || artifacts.event_type || '-';
                    const riskColor = inc.risk_score >= 70 ? '#ef4444' : inc.risk_score >= 40 ? '#f59e0b' : '#6b7280';
                    const statusColor = inc.status === 'OPEN' ? '#ef4444' : inc.status === 'INVESTIGATING' ? '#60a5fa' : '#22c55e';
                    return (
                      <tr
                        key={inc.incident_id || i}
                        className="transition-colors cursor-pointer hover:bg-white/5"
                        style={{ borderTop: i > 0 ? '1px solid rgba(75,85,99,0.1)' : undefined }}
                        onClick={() => navigate('/incidents')}
                      >
                        <td className="px-6 py-4 text-[10px] font-mono" style={{ color: '#60a5fa' }}>
                          {inc.incident_id?.substring(0, 8) || 'N/A'}...
                        </td>
                        <td className="px-6 py-4 text-[10px] whitespace-nowrap font-mono" style={{ color: '#6b7280' }}>
                          {inc.timestamp ? new Date(inc.timestamp).toLocaleString() : '-'}
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-xs font-bold font-mono" style={{ color: riskColor }}>{inc.risk_score}</span>
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-[10px] font-bold uppercase tracking-widest" style={{ color: statusColor }}>{inc.status}</span>
                        </td>
                        <td className="px-6 py-4 text-xs max-w-xs truncate" style={{ color: '#d1d5db' }}>
                          {inc.description || '-'}
                        </td>
                        <td className="px-6 py-4 text-[11px] font-bold" style={{ color: '#d1d5db' }}>{host}</td>
                        <td className="px-6 py-4 text-[10px] font-mono" style={{ color: '#9ca3af' }}>{attackType}</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Save Hunt Dialog */}
      {showSaveDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => setShowSaveDialog(false)}>
          <div className="rounded-lg p-6 w-96" onClick={e => e.stopPropagation()} style={{ background: '#0a0a0a', border: '1px solid rgba(75,85,99,0.5)' }}>
            <h3 className="text-sm font-bold mb-4" style={{ color: '#d1d5db' }}>Save Hunt Query</h3>
            <input
              type="text"
              value={huntName}
              onChange={e => setHuntName(e.target.value)}
              placeholder="Hunt name..."
              className="text-xs rounded px-2 py-1 w-full mb-4"
              style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
              onKeyDown={e => e.key === 'Enter' && handleSaveHunt()}
              autoFocus
            />
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowSaveDialog(false)} className="px-4 py-2 text-xs" style={{ color: '#6b7280' }}>Cancel</button>
              <button onClick={handleSaveHunt} disabled={!huntName.trim()} className="text-xs px-3 py-1.5 rounded" style={{ border: '1px solid #333', color: '#9ca3af', background: 'transparent' }}>Save</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Hunt;
