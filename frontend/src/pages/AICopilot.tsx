import React, { useEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { ArrowLeft, Bot, Send, FileText, Scale, ScrollText, Activity } from 'lucide-react';
import { apiService } from '../services/api';

type ChatMsg = { role: 'user' | 'ai'; text: string; dsl?: any };

const inputStyle: React.CSSProperties = {
  background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db',
};
const cardStyle: React.CSSProperties = {
  background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)',
};

function SectionTitle({ icon, text }: { icon: React.ReactNode; text: string }) {
  return (
    <div className="flex items-center gap-3">
      <span style={{ color: '#60a5fa' }}>{icon}</span>
      <span className="text-sm font-bold uppercase" style={{ color: '#6b7280' }}>{text}</span>
    </div>
  );
}

const AICopilot: React.FC = () => {
  const navigate = useNavigate();
  const [health, setHealth] = useState<any>(null);
  const [question, setQuestion] = useState('');
  const [chat, setChat] = useState<ChatMsg[]>([]);
  const [asking, setAsking] = useState(false);
  const [incidentId, setIncidentId] = useState('');
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState<string | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const [huntRes, setHuntRes] = useState<any>(null);
  const [huntLoading, setHuntLoading] = useState(false);
  const [huntError, setHuntError] = useState<string | null>(null);
  const [createMsg, setCreateMsg] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [providers, setProviders] = useState<any[]>([]);
  const [aiPref, setAiPref] = useState<string>(() => localStorage.getItem('chael_ai_provider') || 'auto');

  useEffect(() => {
    apiService.aiHealth()
      .then((r) => setHealth(r.data))
      .catch(() => setHealth({ status: 'unreachable' }));
    apiService.aiProviders()
      .then((r) => setProviders(r.data.providers || []))
      .catch(() => setProviders([]));
  }, []);

  // Flexible live assistant: free-form SOC Q&A grounded in live SIEM state, with
  // conversation memory. Query-like asks also return a runnable log query.
  const handleAsk = async () => {
    const q = question.trim();
    if (!q || asking) return;
    setAsking(true);
    const history = chat.slice(-10).map((m) => ({
      role: m.role === 'ai' ? 'assistant' : 'user',
      content: m.text.slice(0, 1500),
    }));
    setChat((c) => [...c, { role: 'user', text: q }]);
    setQuestion('');
    try {
      const focus = incidentId.trim() || linkedIncident || undefined;
      const res = await apiService.aiChat(q, history, aiPref, focus);
      const d = res.data || {};
      const meta = `(live · ${d.engine || 'unknown'}${d.siem_grounded ? ' · grounded in SIEM' : ''}${d.incident_found ? ` · incident ${d.incident_id}` : ''})`;
      const text = d.reply
        ? `${d.reply}\n\n${meta}${d.dsl_explanation ? `\nQuery draft: ${d.dsl_explanation}` : ''}`
        : JSON.stringify(d, null, 2);
      setChat((c) => [...c, { role: 'ai', text, dsl: d.dsl }]);
    } catch (err: any) {
      const status = err?.response?.status;
      const detail = err?.response?.data?.detail || err?.message || 'AI query failed';
      const hint = status === 503
        ? `\n\n(Tip: ${detail} — check GROQ_API_KEY / GEMINI_API_KEY in .env and restart ai-assistant-service.)`
        : '';
      setChat((c) => [...c, { role: 'ai', text: `Error: ${detail}${hint}` }]);
    } finally {
      setAsking(false);
    }
  };

  const runDsl = async (dsl: any) => {
    if (!dsl || huntLoading) return;
    setHuntLoading(true);
    setHuntError(null);
    setHuntRes(null);
    setCreateMsg(null);
    try {
      const res = await apiService.advancedHunt(dsl, 100);
      setHuntRes(res.data);
    } catch (err: any) {
      setHuntError(err?.response?.data?.detail || err?.message || 'Hunt query failed');
    } finally {
      setHuntLoading(false);
    }
  };

  const createIncidentFromHunt = async () => {
    const hits = huntRes?.hits || [];
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
        description: `Chael AI hunt (${hits.length} matching logs${hosts.length ? ` on ${hosts.join(', ')}` : ''})`,
        artifacts: { hunt_pack: 'chael-ai', host: hosts[0] || '', attack_type: 'threat_hunt' },
      } as any);
      setCreateMsg(`Incident created: ${(res.data as any)?.incident_id || 'OK'} — triage it on the Incidents page.`);
    } catch (err: any) {
      setCreateMsg(`Create failed: ${err?.response?.data?.detail || err?.message || 'unknown error'}`);
    } finally {
      setCreating(false);
    }
  };

  const runIncidentAction = async (kind: 'explain' | 'triage' | 'report', idOverride?: string) => {
    const id = (idOverride ?? incidentId).trim();
    if (!id || aiLoading) return;
    setAiLoading(kind);
    setAiError(null);
    setAiResult(null);
    try {
      const res = kind === 'explain'
        ? await apiService.aiExplain(id, undefined, aiPref)
        : kind === 'triage'
          ? await apiService.aiTriage(id, undefined, aiPref)
          : await apiService.aiReport(id, undefined, aiPref);
      setAiResult({ kind, data: res.data });
    } catch (err: any) {
      setAiError(err?.response?.data?.detail || err?.message || `AI ${kind} failed`);
    } finally {
      setAiLoading(null);
    }
  };

  // Deep-link from Incidents → Ask AI: ?incident=<id> pre-loads the incident and
  // auto-runs a live explanation so the analyst lands straight in AI support.
  const [searchParams, setSearchParams] = useSearchParams();
  const linkedIncident = searchParams.get('incident') || '';
  const linkedConsumed = useRef(false);
  useEffect(() => {
    if (linkedIncident && !linkedConsumed.current) {
      linkedConsumed.current = true;
      setIncidentId(linkedIncident);
      runIncidentAction('explain', linkedIncident);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [linkedIncident]);

  const aiReady = !!(health && (health.ai_ready || health.groq_ready));
  const activeEngine = health && (health.active || health.model);
  const engineLabel = health
    ? (aiReady ? `${activeEngine} + local fallback` : `${health.disabled_reason || 'Local fallback (no AI key)'}`)
    : 'checking…';

  const providerOptions: { value: string; label: string; cooldown: boolean }[] = [];
  (providers || []).forEach((p: any) => {
    (p.models || []).forEach((m: any) => {
      providerOptions.push({ value: `${p.provider}:${m.model}`, label: `${p.label} — ${m.model}`, cooldown: m.state === 'cooldown' });
    });
  });
  const setProviderPref = (v: string) => {
    setAiPref(v);
    localStorage.setItem('chael_ai_provider', v);
  };
  const selectStyle: React.CSSProperties = { ...inputStyle, fontSize: '10px', padding: '4px 8px' };

  return (
    <div>
      <div className="space-y-6 max-w-7xl mx-auto">
        <button
          onClick={() => navigate('/dashboard')}
          className="flex items-center gap-2 text-sm tracking-widest uppercase transition-colors"
          style={{ color: '#6b7280' }}
          onMouseEnter={(e) => (e.currentTarget.style.color = '#9ca3af')}
          onMouseLeave={(e) => (e.currentTarget.style.color = '#6b7280')}
        >
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </button>

        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2" style={{ color: '#d1d5db' }}>
              <Bot className="w-6 h-6" style={{ color: '#60a5fa' }} /> Chael AI
            </h1>
            <p className="text-sm mt-1" style={{ color: '#6b7280' }}>
              SOC analyst assistant — incident analysis, triage verdicts, log queries. Advisory only, human approves.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {providerOptions.length > 0 && (
              <div className="flex items-center gap-2 text-sm rounded font-mono" style={cardStyle}>
                <span style={{ color: '#6b7280' }}>AI:</span>
                <select
                  value={aiPref}
                  onChange={(e) => setProviderPref(e.target.value)}
                  style={selectStyle}
                  title="Pick the AI to answer. On rate limit it falls over to the next automatically."
                >
                  <option value="auto">Auto (failover order)</option>
                  {providerOptions.map((o) => (
                    <option key={o.value} value={o.value} disabled={o.cooldown}>
                      {o.cooldown ? `${o.label} (cooling…)` : o.label}
                    </option>
                  ))}
                </select>
              </div>
            )}
            <div className="text-sm px-3 py-1.5 rounded font-mono" style={cardStyle}>
              <span style={{ color: '#6b7280' }}>engine: </span>
              <span style={{ color: aiReady ? '#22c55e' : '#ff9500' }}>{engineLabel}</span>
            </div>
          </div>
        </div>

        {!aiReady && health && health.status !== 'unreachable' && (
          <div className="rounded-lg px-4 py-3 text-sm" style={{ background: 'rgba(255,149,0,0.08)', border: '1px solid rgba(255,149,0,0.3)', color: '#ff9500' }}>
            Local analysis active. Add a Groq key (console.groq.com) as GROQ_API_KEY and/or a Gemini key (aistudio.google.com/apikey) as GEMINI_API_KEY and/or an OpenRouter key (openrouter.ai/keys) as OPENROUTER_API_KEY, then set AI_ENABLED=true and restart ai-assistant-service for full reasoning.
          </div>
        )}
        {health && health.status === 'unreachable' && (
          <div className="rounded-lg px-4 py-3 text-sm" style={{ background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)', color: '#ff2d55' }}>
            AI service unreachable. Check that ai-assistant-service is running and /api/ai/ routes resolve.
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Ask Chael AI — flexible live SOC assistant (counts, incidents, hunting, how-to) */}
          <div className="p-5 rounded-lg space-y-4" style={{ ...cardStyle, border: '1px solid rgba(34,197,94,0.25)' }}>
            <div className="flex items-center justify-between flex-wrap gap-2">
              <SectionTitle icon={<Send className="w-4 h-4" />} text="Ask Chael AI (live SOC assistant)" />
              <span className="text-xs font-mono px-2 py-1 rounded" style={{ background: aiReady ? 'rgba(34,197,94,0.1)' : 'rgba(255,149,0,0.1)', color: aiReady ? '#22c55e' : '#ff9500' }}>
                {aiReady ? `live · ${activeEngine}` : 'offline — set GROQ_API_KEY or GEMINI_API_KEY'}
              </span>
            </div>
            <div className="space-y-3 max-h-[34rem] overflow-y-auto custom-scrollbar pr-1">
              {chat.length === 0 && (
                <p className="text-sm italic leading-relaxed" style={{ color: '#6b7280' }}>
                  Ask anything, like a chatbot: "how many incidents do we have right now?",
                  "how many are critical?", "what do I do about incident 380835a1?",
                  "show failed logins in the last hour", "is Kerberoasting happening on our domain?".
                  Answers use live SIEM data; log hunts come with a runnable query button.
                </p>
              )}
              {chat.map((m, i) => (
                <div key={i} className="p-4 rounded text-sm leading-relaxed whitespace-pre-wrap" style={{
                  background: m.role === 'user' ? 'rgba(96,165,250,0.08)' : 'rgba(255,255,255,0.04)',
                  border: '1px solid rgba(75,85,99,0.2)', color: '#d1d5db',
                }}>
                  <span className="font-bold uppercase text-xs block mb-1" style={{ color: m.role === 'user' ? '#60a5fa' : '#22c55e' }}>
                    {m.role === 'user' ? 'Analyst' : 'Chael AI'}
                  </span>
                  {m.text}
                  {m.role === 'ai' && m.dsl && (
                    <button
                      onClick={() => runDsl(m.dsl)}
                      disabled={huntLoading}
                      className="mt-2 text-sm px-3 py-1 rounded font-bold disabled:opacity-40"
                      style={{ border: '1px solid rgba(245,158,11,0.4)', color: '#f59e0b', background: 'rgba(245,158,11,0.08)' }}
                    >
                      {huntLoading ? 'Hunting…' : 'Run this query on logs'}
                    </button>
                  )}
                </div>
              ))}
              {asking && <p className="text-sm animate-pulse" style={{ color: '#6b7280' }}>Chael AI thinking (live)…</p>}
              {(huntLoading || huntError || huntRes) && (
                <div className="p-3 rounded text-sm" style={{ background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.3)' }}>
                  <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
                    <span className="font-bold uppercase text-xs" style={{ color: '#f59e0b' }}>
                      Hunt results ({huntRes?.total ?? 0} hits{huntRes?.took != null ? ` · ${huntRes.took}ms` : ''})
                    </span>
                    {createMsg
                      ? <span className="text-sm" style={{ color: '#22c55e' }}>{createMsg}</span>
                      : <button
                          onClick={createIncidentFromHunt}
                          disabled={!huntRes?.hits?.length || creating}
                          className="text-sm px-2 py-1 rounded font-bold disabled:opacity-30"
                          style={{ border: '1px solid rgba(34,197,94,0.4)', color: '#22c55e', background: 'rgba(34,197,94,0.08)' }}
                        >
                          {creating ? 'Creating…' : 'Create incident'}
                        </button>}
                  </div>
                  {huntLoading && <p className="animate-pulse" style={{ color: '#6b7280' }}>Searching logs…</p>}
                  {huntError && <p style={{ color: '#ff2d55' }}>{huntError}</p>}
                  {(huntRes?.hits || []).slice(0, 10).map((hit: any, i: number) => (
                    <div key={i} className="mt-1 font-mono break-all" style={{ color: '#9ca3af' }}>
                      [{hit.timestamp ? new Date(hit.timestamp).toLocaleString() : ''}] {hit.host || ''} {hit.severity || ''} — {(hit.message || '').slice(0, 180)}
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="flex gap-2 items-end">
              <textarea
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleAsk(); } }}
                placeholder="Ask anything: counts, incidents, hunts, how-to… (Enter to send, Shift+Enter for new line)"
                rows={3}
                className="flex-1 text-sm leading-relaxed rounded px-3 py-2 custom-scrollbar"
                style={{ ...inputStyle, resize: 'vertical', minHeight: '72px' }}
              />
              <button
                onClick={handleAsk}
                disabled={asking || !question.trim()}
                className="text-sm px-4 py-2 rounded font-bold disabled:opacity-40"
                style={{ border: '1px solid rgba(96,165,250,0.4)', color: '#60a5fa', background: 'rgba(96,165,250,0.08)' }}
              >
                Ask
              </button>
            </div>
          </div>

          {/* Incident analysis */}
          <div className="p-5 rounded-lg space-y-4" style={cardStyle}>
            <SectionTitle icon={<FileText className="w-4 h-4" />} text="Incident analysis (explain / triage / report)" />
            {linkedIncident && (
              <div className="flex items-center justify-between gap-2 text-xs px-3 py-2 rounded" style={{ background: 'rgba(168,85,247,0.08)', border: '1px solid rgba(168,85,247,0.3)', color: '#a78bfa' }}>
                <span className="font-mono truncate">Linked from Incidents: {linkedIncident}</span>
                <button
                  onClick={() => { linkedConsumed.current = true; setSearchParams({}); setIncidentId(''); setAiResult(null); }}
                  className="shrink-0 font-bold uppercase hover:underline"
                  style={{ color: '#6b7280' }}
                >
                  Clear
                </button>
              </div>
            )}
            <input
              value={incidentId}
              onChange={(e) => setIncidentId(e.target.value)}
              placeholder="Paste incident_id (from Incidents page)"
              className="w-full text-sm rounded px-3 py-2 font-mono"
              style={inputStyle}
            />
            <div className="flex gap-2 flex-wrap">
              <button
                onClick={() => runIncidentAction('explain')}
                disabled={!incidentId.trim() || !!aiLoading}
                className="text-sm px-3 py-1.5 rounded font-bold disabled:opacity-40 flex items-center gap-1.5"
                style={{ border: '1px solid rgba(96,165,250,0.3)', color: '#60a5fa', background: 'rgba(96,165,250,0.08)' }}
              >
                <FileText className="w-3 h-3" /> {aiLoading === 'explain' ? 'Explaining…' : 'Explain'}
              </button>
              <button
                onClick={() => runIncidentAction('triage')}
                disabled={!incidentId.trim() || !!aiLoading}
                className="text-sm px-3 py-1.5 rounded font-bold disabled:opacity-40 flex items-center gap-1.5"
                style={{ border: '1px solid rgba(34,197,94,0.3)', color: '#22c55e', background: 'rgba(34,197,94,0.08)' }}
              >
                <Scale className="w-3 h-3" /> {aiLoading === 'triage' ? 'Triaging…' : 'Triage verdict'}
              </button>
              <button
                onClick={() => runIncidentAction('report')}
                disabled={!incidentId.trim() || !!aiLoading}
                className="text-sm px-3 py-1.5 rounded font-bold disabled:opacity-40 flex items-center gap-1.5"
                style={{ border: '1px solid #333', color: '#9ca3af' }}
              >
                <ScrollText className="w-3 h-3" /> {aiLoading === 'report' ? 'Drafting…' : 'Draft report'}
              </button>
            </div>
            {aiError && (
              <div className="rounded px-3 py-2 text-sm" style={{ background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)', color: '#ff2d55' }}>
                {aiError}
              </div>
            )}
            {aiResult && (
              <div className="p-4 rounded text-sm leading-relaxed max-h-[38rem] overflow-y-auto custom-scrollbar whitespace-pre-wrap" style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(75,85,99,0.2)', color: '#d1d5db' }}>
                <span className="font-bold uppercase text-xs block mb-2" style={{ color: '#60a5fa' }}>
                  {aiResult.kind} — engine: {aiResult.data?.engine || 'unknown'} · human approval required
                </span>
                {aiResult.kind === 'triage' && aiResult.data?.verdict && (
                  <div className="mb-2">
                    <span className="font-bold">Verdict: {aiResult.data.verdict}</span>
                    <span style={{ color: '#6b7280' }}> (confidence {(aiResult.data.confidence * 100 || 0).toFixed(0)}%)</span>
                  </div>
                )}
                {aiResult.data?.llm_analysis?.analysis || aiResult.data?.executive_summary || JSON.stringify(aiResult.data, null, 2)}
                {aiResult.data?.local_analysis && (
                  <div className="mt-3 pt-3" style={{ borderTop: '1px solid rgba(75,85,99,0.2)' }}>
                    <span className="font-bold uppercase text-xs block mb-1" style={{ color: '#ff9500' }}>Local analysis (always available)</span>
                    {aiResult.data.local_analysis.summary}
                    {(aiResult.data.local_analysis.recommended_actions || []).map((a: string, i: number) => (
                      <div key={i} className="mt-1">• {a}</div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="p-4 rounded-lg flex items-center gap-3 text-sm" style={cardStyle}>
          <Activity className="w-4 h-4 shrink-0" style={{ color: '#6b7280' }} />
          <span style={{ color: '#6b7280' }}>
            Guardrails: PII redacted before any LLM call · prompt-injection screened · responses cached · never auto-closes or contains — every action needs analyst approval on the Incidents / SOAR pages. Powered by Chael AI.
          </span>
        </div>
      </div>
    </div>
  );
};

export default AICopilot;
