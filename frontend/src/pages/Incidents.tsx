import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, ArrowLeft, X, AlertTriangle, Shield, Clock, Target, FileText, Zap, Download, Globe, ExternalLink, Hash, Bot } from 'lucide-react';
import { generateForensicReport } from '../utils/reportGenerator';
import { useIncidents } from '../hooks';
import { apiService } from '../services/api';
import { Incident, InvestigationResult } from '../types';

const riskColor = (score: number) => {
  if (score >= 70) return '#ff2d55';
  if (score >= 40) return '#ff9500';
  // FP band: grey so SOC instantly sees auto-filterable noise.
  return '#9ca3af';
};

const riskLabel = (score: number) => {
  if (score >= 70) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LIKELY FP';
};

const statusStyle: Record<string, { color: string; bg: string }> = {
  OPEN:          { color: '#ff9500', bg: 'rgba(255,149,0,0.12)' },
  INVESTIGATING: { color: '#60a5fa', bg: 'rgba(96,165,250,0.12)' },
  RESOLVED:      { color: '#30d158', bg: 'rgba(48,209,88,0.12)' },
  FALSE_POSITIVE:{ color: '#6b7280', bg: 'rgba(107,114,128,0.12)' },
};

/** Deterministic local action plan — derived from the incident itself, zero
 *  backend calls. Always shown so the analyst never faces a dead-end panel
 *  when live forensics is unreachable or slow. */
function buildLocalActionPlan(incident: Incident): { title: string; steps: string[]; priority: string } {
  const desc = (incident.description || '').toLowerCase();
  const art = incident.artifacts || {};
  const host = art.affected_host || art.host || 'affected host';
  const score = incident.risk_score || 0;
  const priority = score >= 70 ? 'ACT NOW' : score >= 40 ? 'INVESTIGATE TODAY' : 'VERIFY THEN FILTER';
  let title = 'General triage';
  let steps: string[] = [
    `Hunt related logs for ${host} ±30 min (Hunt page).`,
    'Enrich IOCs via Hunt External (AbuseIPDB/Shodan).',
    'Check for lateral movement: same source IP across multiple hosts.',
  ];
  if (desc.includes('brute force') || desc.includes('failed') || desc.includes('4625') || desc.includes('password spray')) {
    title = 'Brute force / credential guessing';
    steps = [
      'Block the source IP at the perimeter firewall.',
      'Force password reset for targeted accounts; check for a successful logon right after the burst (real compromise).',
      'Enforce account lockout + MFA on exposed auth.',
      'Hunt the same source IP across all hosts ±7 days.',
    ];
  } else if (desc.includes('mimikatz') || desc.includes('cobalt') || desc.includes('meterpreter') || desc.includes('malware') || desc.includes('yara')) {
    title = 'Malware / attack tooling — treat host as compromised';
    steps = [
      `Isolate ${host} from the network (keep power on for forensics).`,
      'Collect memory dump + disk image before remediation.',
      'Hunt the same tool/hash across the fleet (Hunt page).',
      'Scan for persistence: scheduled tasks, registry run keys, services.',
    ];
  } else if (desc.includes('powershell') || desc.includes('encoded') || desc.includes('iex')) {
    title = 'Suspicious script execution';
    steps = [
      'Pull the full command lines — look for encoded/IEX/download patterns.',
      'Constrain PowerShell (ConstrainedLanguage mode) if abuse is confirmed.',
      `Isolate ${host} if the script reached out to external infrastructure.`,
      'Hunt identical command lines fleet-wide.',
    ];
  } else if (desc.includes('log cleared') || desc.includes('1102') || desc.includes('audit policy') || desc.includes('anti-forensics')) {
    title = 'Anti-forensics — preserve what remains';
    steps = [
      'Preserve remaining logs immediately; snapshot the host.',
      `Treat ${host} as hostile until proven otherwise.`,
      'Hunt for the intrusion that preceded the wipe (±24h).',
    ];
  } else if (desc.includes('nmap') || desc.includes('scan') || desc.includes('masscan') || desc.includes('port scan')) {
    title = 'Reconnaissance scan';
    steps = [
      'Confirm the scanner is NOT an approved vuln scanner (allowlist check).',
      'If unauthorized: block source IP, hunt for follow-on exploitation.',
      'If approved: verify against the change ticket, then mark FALSE_POSITIVE.',
    ];
  } else if (desc.includes('kerberoast') || desc.includes('4769') || desc.includes('as-rep') || desc.includes('4771') || desc.includes('golden') || desc.includes('silver ticket') || desc.includes('0x17')) {
    title = 'Kerberos attack (roasting / forged ticket)';
    steps = [
      `Isolate the requesting host; rotate the targeted service-account password.`,
      'If forgery is suspected: reset KRBTGT twice, then rotate service passwords.',
      'Enforce AES-only Kerberos + pre-auth everywhere.',
      'Hunt 4769/4771 bursts domain-wide ±7 days.',
    ];
  } else if (desc.includes('pass-the-hash') || desc.includes('pass the hash') || desc.includes('ntlm') || desc.includes('lateral') || desc.includes('rdp') || desc.includes('4624')) {
    title = 'Lateral movement';
    steps = [
      'Isolate the source host; block its IP at the perimeter.',
      'Map source→destination logons (4624/4778/4779) to scope the spread.',
      'Rotate all credentials that traversed the compromised host.',
    ];
  } else if (desc.includes('dns') && (desc.includes('tunnel') || desc.includes('c2') || desc.includes('query'))) {
    title = 'Possible DNS tunneling / C2';
    steps = [
      `Isolate ${host}; block the suspicious domain at the DNS firewall.`,
      'Capture full DNS + flow logs ±24h and inspect longest labels.',
      'Hunt other hosts querying the same domain pattern.',
    ];
  } else if (desc.includes('ransomware') || desc.includes('.crypt') || desc.includes('encrypt')) {
    title = 'Possible ransomware — speed matters';
    steps = [
      `Isolate ${host} immediately; check file-write velocity + backups.`,
      'Identify patient zero via earliest encryption timestamp.',
      'Block related IOCs fleet-wide before eradication.',
    ];
  } else if (desc.includes('persistence') || desc.includes('scheduled task') || desc.includes('4698') || desc.includes('service installed') || desc.includes('registry')) {
    title = 'Persistence mechanism';
    steps = [
      'Verify the task/service signer and creating process (SCCM/Intune/Ansible = likely legit).',
      'Preserve the binary before removal; image the host.',
      'Sweep the fleet for identical task names/hashes/run keys.',
    ];
  }
  if (score < 40) {
    steps = ['Likely noise — run the allowlist/maintenance-window checks first:', ...steps];
  }
  return { title, steps, priority };
}

function InvestigationPanel({ incident, result, error, onRetry, onResolve, onMitigate, onClose }: {
  incident: Incident;
  result: InvestigationResult | null;
  error: string | null;
  onRetry: () => void;
  onResolve: () => void;
  onMitigate: (type: string, target: string) => void;
  onClose: () => void;
}) {
  const [isMitigating, setIsMitigating] = useState<string | null>(null);
  const [executingAll, setExecutingAll] = useState(false);

  const handleExport = () => {
    if (result) {
      generateForensicReport(incident, result);
    }
  };

  const handleMitigateAction = async (step: string) => {
    let type = "GENERAL_MITIGATION";
    let target = incident.artifacts?.affected_host || "UNKNOWN_TARGET";

    if (step.toLowerCase().includes("block ip") || step.toLowerCase().includes("firewall")) {
      type = "BLOCK_IP";
      target = result?.ioc_matches.find(i => i.type === 'IP')?.ioc || target;
    } else if (step.toLowerCase().includes("disable") || step.toLowerCase().includes("account")) {
      type = "DISABLE_USER";
      target = incident.artifacts?.user || "SUSPECT_ACCOUNT";
    }

    setIsMitigating(step);
    await onMitigate(type, target);
    setTimeout(() => setIsMitigating(null), 1500);
  };

  const handleExecuteAllMitigation = async () => {
    if (!result?.follow_up_steps) return;
    setExecutingAll(true);
    for (const step of result.follow_up_steps) {
      await handleMitigateAction(step);
      // Small delay between actions
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    setExecutingAll(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(10,10,10,0.9)', backdropFilter: 'blur(6px)' }}>
      <div className="relative w-full max-w-4xl max-h-[95vh] overflow-hidden rounded-lg flex flex-col"
        style={{ background: '#0a0a0a', border: '1px solid rgba(75,85,99,0.2)' }}>

        {/* Header */}
        <div className="px-6 py-5 flex items-center justify-between shrink-0"
          style={{ background: '#0a0a0a', borderBottom: '1px solid rgba(75,85,99,0.2)' }}>
          <div className="flex items-center gap-4">
            <div className="p-2 rounded" style={{ background: 'rgba(255,255,255,0.03)' }}>
              <FileText className="w-6 h-6" style={{ color: '#9ca3af' }} />
            </div>
            <div>
              <span className="font-bold text-sm uppercase block" style={{ color: '#d1d5db' }}>
                Investigation Report
              </span>
              <span className="text-xs" style={{ color: '#6b7280' }}>{incident.incident_id}</span>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={handleExport}
              disabled={!result}
              className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest px-4 py-2 rounded transition-all disabled:opacity-30"
              style={{ border: '1px solid #333', color: '#d1d5db' }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.05)'; }}
              onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
            >
              <FileText className="w-3.5 h-3.5" /> Generate PDF Report
            </button>
            <button onClick={onClose} className="p-2 rounded transition-colors" style={{ color: '#6b7280' }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.05)'; }}
              onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
            >
              <X className="w-6 h-6" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-8 space-y-10 custom-scrollbar">
          {/* Metadata Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-4 rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
              <div className="text-xs font-bold uppercase text-xs mb-1" style={{ color: '#6b7280' }}>Risk Assessment</div>
              <div className="text-3xl font-mono font-bold" style={{ color: riskColor(incident.risk_score) }}>
                {incident.risk_score}<span className="text-sm opacity-40">/100 · {riskLabel(incident.risk_score)}</span>
              </div>
              {incident.risk_score < 40 && (
                <div className="text-xs font-bold mt-1" style={{ color: '#9ca3af' }}>LIKELY FP — low-fidelity noise, verify allowlist then filter</div>
              )}
            </div>
            <div className="p-4 rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
              <div className="text-xs font-bold uppercase text-xs mb-1" style={{ color: '#6b7280' }}>Incident Lifecycle</div>
              <div className="text-sm font-bold mt-1" style={{ color: statusStyle[incident.status]?.color || '#6b7280' }}>
                {incident.status}
              </div>
              <div className="text-xs mt-1" style={{ color: '#6b7280' }}>Status synchronized with backend</div>
            </div>
            <div className="p-4 rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
              <div className="text-xs font-bold uppercase text-xs mb-1" style={{ color: '#6b7280' }}>Time Latency</div>
              <div className="text-[11px] mt-1" style={{ color: '#9ca3af' }}>
                {new Date(incident.timestamp).toLocaleString()}
              </div>
            </div>
          </div>

          {error && (
            <div className="rounded-lg px-4 py-3 text-sm flex items-center justify-between gap-4" style={{ background: 'rgba(255,149,0,0.08)', border: '1px solid rgba(255,149,0,0.3)', color: '#ff9500' }}>
              <span>Live forensics unavailable ({error}). Action plan below is generated from the incident itself — no backend needed.</span>
              <button onClick={onRetry} className="text-xs font-bold uppercase tracking-widest px-4 py-1.5 rounded shrink-0" style={{ border: '1px solid rgba(255,149,0,0.4)', color: '#ff9500' }}>
                Retry live analysis
              </button>
            </div>
          )}

          {/* Actions to Take — always visible, derived from the incident itself */}
          {(() => {
            const plan = buildLocalActionPlan(incident);
            const liveSteps = result?.recommended_actions?.length ? result.recommended_actions : null;
            return (
              <div className="space-y-4 p-5 rounded-lg" style={{ background: 'rgba(34,197,94,0.04)', border: '1px solid rgba(34,197,94,0.25)' }}>
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center gap-3">
                    <Zap className="w-5 h-5" style={{ color: '#22c55e' }} />
                    <span className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>
                      Actions to Take — {plan.title}{liveSteps ? ' (live)' : ' (from incident)'}
                    </span>
                  </div>
                  <span className="text-xs font-bold px-2 py-0.5 rounded" style={{
                    background: plan.priority === 'ACT NOW' ? 'rgba(255,45,85,0.15)' : plan.priority === 'INVESTIGATE TODAY' ? 'rgba(255,149,0,0.15)' : 'rgba(107,114,128,0.15)',
                    color: plan.priority === 'ACT NOW' ? '#ff2d55' : plan.priority === 'INVESTIGATE TODAY' ? '#ff9500' : '#9ca3af',
                  }}>
                    {plan.priority}
                  </span>
                </div>
                <div className="space-y-2">
                  {(liveSteps || plan.steps).map((step, i) => (
                    <div key={i} className="flex items-start gap-3 p-3 rounded-lg" style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.06)' }}>
                      <span className="shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold" style={{ background: 'rgba(34,197,94,0.12)', border: '1px solid rgba(34,197,94,0.35)', color: '#22c55e' }}>{i + 1}</span>
                      <span className="text-sm leading-snug" style={{ color: '#d1d5db' }}>{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            );
          })()}

          {result ? (
            <>
              {/* Evidence locker — always available, independent of live forensics */}
              <EvidenceSection incident={incident} />
              {/* Timeline & Analysis Narrative */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
                <div className="space-y-6">
                  <div className="flex items-center gap-3">
                    <Clock className="w-5 h-5" style={{ color: '#9ca3af' }} />
                    <span className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Timeline</span>
                  </div>
                  <div className="space-y-6">
                    {result.walkthrough?.map((step, i) => (
                      <div key={i} className="flex items-start gap-3">
                        <span className="shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold" style={{ background: i === 0 ? 'rgba(34,197,94,0.1)' : 'rgba(255,255,255,0.05)', border: '1px solid rgba(75,85,99,0.2)', color: i === 0 ? '#22c55e' : '#6b7280' }}>{i + 1}</span>
                        <p className="text-xs leading-relaxed pt-0.5" style={{ color: '#d1d5db' }}>
                          {step}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-10">
                  {/* MITRE ATT&CK */}
                  {result.mitre_technique && (
                    <div className="space-y-4">
                      <div className="flex items-center gap-3">
                        <Target className="w-5 h-5" style={{ color: '#ff9500' }} />
                        <span className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>MITRE ATT&CK Mapping</span>
                      </div>
                      <div className="grid grid-cols-3 gap-3">
                        <div className="p-3 rounded" style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.05)' }}>
                          <span className="text-[8px] uppercase tracking-widest block mb-1" style={{ color: '#6b7280' }}>Technique</span>
                          <span className="text-[11px] font-mono" style={{ color: '#d1d5db' }}>{result.mitre_technique.id}</span>
                        </div>
                        <div className="p-3 rounded" style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.05)' }}>
                          <span className="text-[8px] uppercase tracking-widest block mb-1" style={{ color: '#6b7280' }}>Name</span>
                          <span className="text-[11px] font-mono" style={{ color: '#d1d5db' }}>{result.mitre_technique.name}</span>
                        </div>
                        <div className="p-3 rounded" style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.05)' }}>
                          <span className="text-[8px] uppercase tracking-widest block mb-1" style={{ color: '#6b7280' }}>Tactic</span>
                          <span className="text-[11px] font-mono" style={{ color: '#d1d5db' }}>{result.mitre_technique.tactic}</span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* IOC Matrix */}
                  <div className="space-y-4">
                    <div className="flex items-center gap-3">
                      <Target className="w-5 h-5" style={{ color: '#ff9500' }} />
                      <span className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Artifact Correlation Matrix</span>
                    </div>
                    <div className="grid gap-3">
                      {result.ioc_matches.map((ioc, i) => (
                        <div key={i} className="flex justify-between items-center p-3 rounded transition-all" style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.05)' }}
                          onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(245,158,11,0.3)'; }}
                          onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.05)'; }}
                        >
                          <div className="flex flex-col">
                            <span className="text-[11px] font-mono" style={{ color: '#d1d5db' }}>{ioc.ioc}</span>
                            <span className="text-xs uppercase tracking-widest" style={{ color: '#6b7280' }}>{ioc.type}</span>
                            {ioc.context && <span className="text-[8px] mt-0.5 italic" style={{ color: '#6b7280' }}>{ioc.context}</span>}
                          </div>
                          <div className="flex items-center gap-2">
                            <a href={`/logs?q=${encodeURIComponent(ioc.ioc)}`} title="Pivot: hunt this IOC in logs"
                              className="text-xs font-bold px-2 py-1 rounded" style={{ border: '1px solid #333', color: '#60a5fa' }}>
                              Logs
                            </a>
                            <div className="w-16 h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.1)' }}>
                              <div className="h-full bg-orange-500" style={{ width: `${ioc.confidence * 100}%` }} />
                            </div>
                            <span className="text-xs font-bold text-orange-400">{(ioc.confidence * 100).toFixed(0)}%</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Asset Impact */}
                  <div className="space-y-4">
                    <div className="flex items-center gap-3">
                      <AlertTriangle className="w-5 h-5 text-red-500" />
                      <span className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Targeted Infrastructure</span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {result.affected_assets.map((asset, i) => (
                        <div key={i} className="px-3 py-1.5 rounded flex items-center gap-2" style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)' }}>
                          <div className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                          <span className="text-xs font-mono text-red-400">{asset.hostname}</span>
                          <span className="text-[8px] ml-1" style={{ color: '#6b7280' }}>({asset.role})</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Threat Intel Enrichment */}
                  {result.threat_intel_enrichment && Object.keys(result.threat_intel_enrichment).length > 0 && (
                    <div className="space-y-4">
                      <div className="flex items-center gap-3">
                        <Shield className="w-5 h-5" style={{ color: '#22c55e' }} />
                        <span className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Threat Intelligence Enrichment</span>
                      </div>
                      <div className="space-y-2">
                        {Object.entries(result.threat_intel_enrichment).map(([key, val]: [string, any]) => (
                          <div key={key} className="p-3 rounded" style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.05)' }}>
                            <span className="text-xs font-mono font-bold" style={{ color: '#d1d5db' }}>{key}</span>
                            {val.virustotal && (
                              <div className="mt-2 grid grid-cols-5 gap-2 text-xs">
                                <div><span style={{ color: '#6b7280' }}>Malicious:</span> <span className="text-red-400">{val.virustotal.malicious}</span></div>
                                <div><span style={{ color: '#6b7280' }}>Suspicious:</span> <span className="text-orange-400">{val.virustotal.suspicious}</span></div>
                                <div><span style={{ color: '#6b7280' }}>Harmless:</span> <span className="text-green-400">{val.virustotal.harmless}</span></div>
                                <div><span style={{ color: '#6b7280' }}>Reputation:</span> <span style={{ color: '#d1d5db' }}>{val.virustotal.reputation}</span></div>
                                <div><span style={{ color: '#6b7280' }}>Country:</span> <span style={{ color: '#d1d5db' }}>{val.virustotal.country}</span></div>
                              </div>
                            )}
                            {val.abuseipdb && (
                              <div className="mt-2 text-xs">
                                <span style={{ color: '#6b7280' }}>AbuseIPDB:</span>{' '}
                                <span className={val.abuseipdb.abuse_confidence_score > 50 ? 'text-red-400' : 'text-green-400'}>
                                  {val.abuseipdb.abuse_confidence_score}% confidence
                                </span>
                                <span style={{ color: '#6b7280' }} className="ml-2">({val.abuseipdb.total_reports} reports)</span>
                              </div>
                            )}
                            {val.geoip && (
                              <div className="mt-2 text-xs">
                                <span style={{ color: '#6b7280' }}>GeoIP:</span>{' '}
                                <span style={{ color: '#d1d5db' }}>{[val.geoip.city, val.geoip.country].filter(Boolean).join(', ')}</span>
                                {val.geoip.isp && <span style={{ color: '#6b7280' }} className="ml-2">ISP: {val.geoip.isp}</span>}
                              </div>
                            )}
                            {!val.virustotal && !val.abuseipdb && !val.geoip && (
                              <span className="text-xs italic" style={{ color: '#6b7280' }}>No enrichment data available (API keys may be unconfigured)</span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* SOAR Playbook Roadmap */}
              <div className="space-y-6 pt-6" style={{ borderTop: '1px solid rgba(75,85,99,0.3)' }}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Zap className="w-5 h-5" style={{ color: '#22c55e' }} />
                    <span className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Adaptive Response Playbook</span>
                  </div>
                  <span className="text-xs italic" style={{ color: '#6b7280' }}>Click steps to execute automated mitigation</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {result.follow_up_steps?.map((step, i) => {
                    const isActive = isMitigating === step;
                    return (
                      <div
                        key={i}
                        onClick={() => handleMitigateAction(step)}
                        className={`group p-4 rounded-lg border transition-all cursor-pointer flex items-center gap-4 ${isActive ? 'scale-[0.98]' : ''}`}
                        style={{
                          background: isActive ? 'rgba(34,197,94,0.1)' : 'rgba(0,0,0,0.2)',
                          borderColor: isActive ? 'rgba(34,197,94,0.5)' : 'rgba(255,255,255,0.05)',
                        }}
                        onMouseEnter={e => { if (!isActive) { e.currentTarget.style.borderColor = 'rgba(34,197,94,0.5)'; } }}
                        onMouseLeave={e => { if (!isActive) { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.05)'; } }}
                      >
                        <div className={`shrink-0 w-8 h-8 rounded-full border flex items-center justify-center transition-all`}
                          style={{
                            background: isActive ? '#22c55e' : 'transparent',
                            borderColor: isActive ? '#22c55e' : '#6b7280',
                          }}
                          onMouseEnter={e => { if (!isActive) { e.currentTarget.style.borderColor = '#22c55e'; e.currentTarget.style.background = 'rgba(34,197,94,0.1)'; } }}
                          onMouseLeave={e => { if (!isActive) { e.currentTarget.style.borderColor = '#6b7280'; e.currentTarget.style.background = 'transparent'; } }}
                        >
                          {isActive ? <Zap className="w-4 h-4 text-black animate-pulse" /> : <span className="text-xs font-bold" style={{ color: '#d1d5db' }}>{i + 1}</span>}
                        </div>
                        <div className="flex-1">
                          <p className="text-xs leading-snug transition-colors" style={{ color: '#d1d5db' }}
                            onMouseEnter={e => { if (!isActive) { e.currentTarget.style.color = '#22c55e'; } }}
                            onMouseLeave={e => { if (!isActive) { e.currentTarget.style.color = '#d1d5db'; } }}
                          >{step}</p>
                          {isActive && <span className="text-[8px] font-bold uppercase tracking-[0.2em] animate-pulse" style={{ color: '#22c55e' }}>Executing Action...</span>}
                        </div>
                        <Zap className="w-4 h-4 opacity-0 group-hover:opacity-100 transition-opacity" style={{ color: '#22c55e' }} />
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* What Should I Do */}
              {result && (result.soc_verdict_guide || result.recommended_actions?.length || result.false_positive_checklist?.length) && (
                <div className="space-y-6 pt-6" style={{ borderTop: '1px solid rgba(75,85,99,0.3)' }}>
                  <div className="flex items-center gap-3">
                    <Shield className="w-5 h-5" style={{ color: '#9ca3af' }} />
                    <span className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Guidance</span>
                  </div>

                  {result.soc_verdict_guide && (
                    <div className="p-4 rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
                      <span className="text-xs uppercase font-bold" style={{ color: '#9ca3af' }}>SOC Verdict Guide</span>
                      <p className="text-xs mt-2 leading-relaxed" style={{ color: '#6b7280' }}>{result.soc_verdict_guide}</p>
                    </div>
                  )}

                  {result.recommended_actions?.length > 0 && (
                    <div>
                      <span className="text-xs uppercase tracking-[0.2em] font-bold" style={{ color: '#22c55e' }}>Recommended Actions</span>
                      <div className="mt-2 space-y-2">
                        {result.recommended_actions.map((action, i) => (
                          <div key={i} className="flex items-start gap-3 p-3 rounded-lg" style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.05)' }}>
                            <span className="shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold" style={{ background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', color: '#22c55e' }}>{i + 1}</span>
                            <span className="text-xs leading-snug" style={{ color: '#6b7280' }}>{action}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {result.false_positive_checklist && result.false_positive_checklist.length > 0 && (
                    <div>
                      <span className="text-xs uppercase tracking-[0.2em] font-bold" style={{ color: '#ff9500' }}>False Positive Verification Steps</span>
                      <div className="mt-2 space-y-2">
                        {result.false_positive_checklist.map((check, i) => (
                          <div key={i} className="flex items-start gap-3 p-3 rounded-lg" style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.05)' }}>
                            <span className="shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold" style={{ background: 'rgba(255,149,0,0.1)', border: '1px solid rgba(255,149,0,0.3)', color: '#ff9500' }}>+</span>
                            <span className="text-xs leading-snug" style={{ color: '#6b7280' }}>{check}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Action Bar */}
              <div className="pt-6 flex justify-between items-center" style={{ borderTop: '1px solid rgba(75,85,99,0.2)' }}>
                <div className="flex flex-col">
                   <span className="text-xs uppercase" style={{ color: '#6b7280' }}>Analyst Confidence</span>
                   <span className="text-xs font-bold" style={{ color: '#9ca3af' }}>HEURISTIC_VALIDATED</span>
                </div>
                 <div className="flex gap-4">
                   <button onClick={onClose} className="px-6 py-2 text-xs font-bold uppercase tracking-widest transition-colors" style={{ color: '#6b7280' }}
                     onMouseEnter={e => { e.currentTarget.style.color = '#d1d5db'; }}
                     onMouseLeave={e => { e.currentTarget.style.color = '#6b7280'; }}
                   >
                     Dismiss
                   </button>
                   {result?.follow_up_steps && (
                     <button
                       onClick={handleExecuteAllMitigation}
                       disabled={executingAll}
                       className="text-xs font-bold uppercase tracking-widest px-6 py-2 rounded disabled:opacity-50"
                       style={{ background: executingAll ? 'rgba(245,158,11,0.5)' : 'rgba(245,158,11,0.8)', color: '#0a0a0a', border: 'none' }}
                     >
                       {executingAll ? 'Executing...' : 'Execute Mitigation'}
                     </button>
                   )}
                   <button onClick={onResolve} className="text-xs font-bold uppercase tracking-widest px-6 py-2 rounded" style={{ border: '1px solid #333', color: '#9ca3af' }}>
                     Acknowledge & Resolve Incident
                   </button>
                 </div>
              </div>
            </>
          ) : (
            <div className="rounded-lg px-4 py-3 text-sm flex items-center justify-between gap-4" style={{ background: 'rgba(96,165,250,0.06)', border: '1px solid rgba(96,165,250,0.25)', color: '#60a5fa' }}>
              <span className="flex items-center gap-3">
                <span className="w-4 h-4 border-2 border-t-transparent rounded-full animate-spin inline-block" style={{ borderColor: 'rgba(96,165,250,0.3)', borderTopColor: '#60a5fa' }} />
                Fetching live forensic detail — the action plan above is ready to work from now.
              </span>
              <button onClick={onClose} className="text-xs font-bold uppercase tracking-widest px-4 py-1.5 rounded shrink-0" style={{ border: '1px solid #333', color: '#9ca3af' }}>
                Back
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/** Evidence locker — simple chain-of-custody: seize (hash-sealed) →
 *  transfer (custody hop) → verify (re-hash). Legal hold blocks close + purge. */
function EvidenceSection({ incident }: { incident: Incident }) {
  const [items, setItems] = useState<any[]>(incident.evidence || []);
  const [hold, setHold] = useState(!!incident.legal_hold);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [fType, setFType] = useState('log-slice');
  const [fTitle, setFTitle] = useState('');
  const [fSha, setFSha] = useState('');
  const [fDesc, setFDesc] = useState('');
  const [transferTo, setTransferTo] = useState<Record<string, string>>({});

  const reload = async () => {
    try {
      const res = await apiService.getEvidence(incident.incident_id);
      setItems(res.data.evidence || []);
      setHold(!!res.data.legal_hold);
    } catch {}
  };

  useEffect(() => { reload(); }, [incident.incident_id]);

  const seize = async () => {
    if (!fTitle.trim()) { setErr('Evidence needs a title'); return; }
    setBusy(true); setErr(null);
    try {
      const res = await apiService.seizeEvidence(incident.incident_id, {
        type: fType, title: fTitle.trim(), description: fDesc.trim(), sha256: fSha.trim(),
        source_host: incident.artifacts?.host || incident.artifacts?.affected_host || '',
      });
      setItems(prev => [...prev, res.data.evidence]);
      setFTitle(''); setFSha(''); setFDesc(''); setShowForm(false);
    } catch (e: any) {
      setErr(e?.response?.data?.detail || e.message || 'Seize failed');
    } finally { setBusy(false); }
  };

  const transfer = async (evidenceId: string) => {
    const to = (transferTo[evidenceId] || '').trim();
    if (!to) { setErr('Enter the new custodian first'); return; }
    setBusy(true); setErr(null);
    try {
      const res = await apiService.transferEvidence(incident.incident_id, evidenceId, to, 'custody handoff');
      setItems(prev => prev.map(i => i.evidence_id === evidenceId ? res.data.evidence : i));
    } catch (e: any) {
      setErr(e?.response?.data?.detail || e.message || 'Transfer failed');
    } finally { setBusy(false); }
  };

  const verify = async (evidenceId: string) => {
    setBusy(true); setErr(null);
    try {
      const res = await apiService.verifyEvidence(incident.incident_id, evidenceId);
      setItems(prev => prev.map(i => i.evidence_id === evidenceId
        ? { ...i, verified: res.data.ok, verified_at: res.data.verified_at } : i));
      if (!res.data.ok) setErr('Hash mismatch — evidence may have been altered');
    } catch (e: any) {
      setErr(e?.response?.data?.detail || e.message || 'Verify failed');
    } finally { setBusy(false); }
  };

  const toggleHold = async () => {
    setBusy(true); setErr(null);
    try {
      const res = await apiService.setLegalHold(incident.incident_id, !hold);
      setHold(res.data.legal_hold);
    } catch (e: any) {
      setErr(e?.response?.data?.detail || e.message || 'Hold update failed');
    } finally { setBusy(false); }
  };

  return (
    <div className="space-y-4 p-5 rounded-lg" style={{ background: 'rgba(96,165,250,0.04)', border: '1px solid rgba(96,165,250,0.25)' }}>
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-3">
          <Hash className="w-5 h-5" style={{ color: '#60a5fa' }} />
          <span className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>
            Evidence Locker — chain of custody ({items.length})
          </span>
          {hold && (
            <span className="text-xs font-bold px-2 py-0.5 rounded" style={{ background: 'rgba(255,45,85,0.15)', color: '#ff2d55' }}>
              LEGAL HOLD — purge &amp; close blocked
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button onClick={toggleHold} disabled={busy}
            className="text-xs font-bold uppercase px-3 py-1.5 rounded disabled:opacity-40"
            style={{ border: '1px solid rgba(255,45,85,0.4)', color: hold ? '#30d158' : '#ff2d55' }}>
            {hold ? 'Release hold' : 'Legal hold'}
          </button>
          <button onClick={() => setShowForm(!showForm)}
            className="text-xs font-bold uppercase px-3 py-1.5 rounded"
            style={{ border: '1px solid #333', color: '#d1d5db' }}>
            {showForm ? 'Cancel' : 'Seize evidence'}
          </button>
        </div>
      </div>
      {err && <div className="text-xs" style={{ color: '#ff2d55' }}>{err}</div>}
      {showForm && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-4 rounded-lg" style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.06)' }}>
          <select value={fType} onChange={e => setFType(e.target.value)} className="text-xs rounded px-2 py-2"
            style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}>
            {['log-slice', 'file', 'hash', 'image', 'triage', 'note'].map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <input value={fTitle} onChange={e => setFTitle(e.target.value)} placeholder="Title — e.g. auth.log slice 09:55-10:00"
            className="text-xs rounded px-2 py-2" style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }} />
          <input value={fSha} onChange={e => setFSha(e.target.value)} placeholder="SHA-256 (optional, paste if known)"
            className="text-xs rounded px-2 py-2 font-mono" style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }} />
          <input value={fDesc} onChange={e => setFDesc(e.target.value)} placeholder="Description — what/where/when collected"
            className="text-xs rounded px-2 py-2" style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }} />
          <div className="md:col-span-2">
            <button onClick={seize} disabled={busy} className="text-xs font-bold uppercase px-4 py-2 rounded disabled:opacity-40"
              style={{ background: 'rgba(96,165,250,0.8)', color: '#0a0a0a', border: 'none' }}>
              {busy ? 'Sealing...' : 'Seal & store evidence'}
            </button>
          </div>
        </div>
      )}
      <div className="space-y-2">
        {items.length === 0 && (
          <div className="text-xs italic" style={{ color: '#6b7280' }}>
            No evidence seized yet. Seize the log slice + hashes backing this incident before containment.
          </div>
        )}
        {items.map(ev => (
          <div key={ev.evidence_id} className="p-3 rounded-lg" style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.06)' }}>
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold px-2 py-0.5 rounded uppercase" style={{ background: 'rgba(96,165,250,0.12)', color: '#60a5fa' }}>{ev.type}</span>
                <span className="text-xs font-bold" style={{ color: '#d1d5db' }}>{ev.title}</span>
                {ev.verified
                  ? <span className="text-xs font-bold" style={{ color: '#30d158' }}>SEALED ✓</span>
                  : <span className="text-xs" style={{ color: '#ff9500' }}>unverified</span>}
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => verify(ev.evidence_id)} disabled={busy} className="text-xs px-2 py-1 rounded disabled:opacity-40"
                  style={{ border: '1px solid #333', color: '#9ca3af' }}>Verify</button>
              </div>
            </div>
            {ev.sha256 && <div className="text-xs font-mono mt-1 break-all" style={{ color: '#6b7280' }}>sha256: {ev.sha256}</div>}
            {ev.description && <div className="text-xs mt-1" style={{ color: '#9ca3af' }}>{ev.description}</div>}
            <div className="text-xs mt-2" style={{ color: '#6b7280' }}>
              Custody: {(ev.custody || []).map((c: any, i: number) => (
                <span key={i}>{i > 0 ? ' → ' : ''}{c.to || c.actor}{c.reason ? ` (${c.reason})` : ''}</span>
              ))}
            </div>
            <div className="flex items-center gap-2 mt-2">
              <input value={transferTo[ev.evidence_id] || ''} onChange={e => setTransferTo(p => ({ ...p, [ev.evidence_id]: e.target.value }))}
                placeholder="Hand off to (analyst name)" className="text-xs rounded px-2 py-1 w-48"
                style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }} />
              <button onClick={() => transfer(ev.evidence_id)} disabled={busy} className="text-xs px-2 py-1 rounded disabled:opacity-40"
                style={{ border: '1px solid #333', color: '#9ca3af' }}>Transfer</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function Incidents() {
  const navigate = useNavigate();
  const { incidents, loading, error: incidentsError, investigate, resolveIncident, mitigate, fetchIncidents } = useIncidents();
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'OPEN' | 'INVESTIGATING' | 'RESOLVED'>('all');
  const [investigatingId, setInvestigatingId] = useState<string | null>(null);
  const [investigationResults, setInvestigationResults] = useState<Record<string, InvestigationResult>>({});
  const [investigationError, setInvestigationError] = useState<Record<string, string | null>>({});
  const [activePanel, setActivePanel] = useState<Incident | null>(null);
  const [externalHuntLoading, setExternalHuntLoading] = useState<string | null>(null);
  const [externalHuntResults, setExternalHuntResults] = useState<Record<string, any>>({});
  const [externalHuntError, setExternalHuntError] = useState<Record<string, string | null>>({});
  const [activeExternalHunt, setActiveExternalHunt] = useState<string | null>(null);
  const [retrying, setRetrying] = useState(false);

  const handleRetry = async () => {
    setRetrying(true);
    try { await fetchIncidents(); } catch {} finally { setRetrying(false); }
  };

  const filteredIncidents = incidents.filter((inc) => {
    const matchesSearch = inc.description?.toLowerCase().includes(search.toLowerCase()) ||
      inc.incident_id.toLowerCase().includes(search.toLowerCase());
    const matchesFilter = filter === 'all' || inc.status === filter;
    return matchesSearch && matchesFilter;
  });

  const handleInvestigate = async (incident: Incident, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setActivePanel(incident);
    setInvestigatingId(incident.incident_id);
    setInvestigationError(prev => ({ ...prev, [incident.incident_id]: null }));
    
    try {
      const result = await investigate(incident.incident_id);
      setInvestigationResults(prev => ({ ...prev, [incident.incident_id]: result }));
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'Investigation failed';
      const isTimeout = msg.includes('timeout') || msg.includes('Timeout');
      setInvestigationError(prev => ({ ...prev, [incident.incident_id]: isTimeout
        ? 'Investigation timed out — incident data may be too large. Try again shortly.'
        : msg
      }));
    } finally {
      setInvestigatingId(null);
    }
  };

  const handleResolve = async (id: string) => {
    try {
      await resolveIncident(id, 'RESOLVED');
      setActivePanel(null);
    } catch (err) {
      console.error('Failed to resolve incident:', err);
    }
  };

  const handleMitigate = async (type: string, target: string) => {
    if (!activePanel) return;
    try {
      await mitigate(activePanel.incident_id, {
        action_type: type,
        target: target,
        reason: `Automated mitigation triggered from forensic roadmap for incident ${activePanel.incident_id}`
      });
    } catch (err) {
      console.error('SOAR Execution failed:', err);
    }
  };

  const handleExternalHunt = async (incident: Incident, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    const id = incident.incident_id;
    setActiveExternalHunt(id);
    setExternalHuntLoading(id);
    setExternalHuntError(prev => ({ ...prev, [id]: null }));
    try {
      const response = await apiService.externalThreatHunt(id);
      setExternalHuntResults(prev => ({ ...prev, [id]: response.data }));
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'External hunt failed';
      const isTimeout = msg.includes('timeout') || msg.includes('Timeout');
      setExternalHuntError(prev => ({ ...prev, [id]: isTimeout
        ? 'External enrichment timed out — network may be unavailable. IOCs extracted locally only.'
        : msg
      }));
    } finally {
      setExternalHuntLoading(null);
    }
  };

  const handleAskAi = (incident: Incident, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    // Deep-link into the Chael AI page with the incident pre-loaded: the analyst
    // gets full live AI support (explain/triage/chat/hunt) instead of a modal snapshot.
    navigate(`/ai-copilot?incident=${encodeURIComponent(incident.incident_id)}`);
  };

  const [exportError, setExportError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  const handleExportCSV = async () => {
    setExporting(true);
    setExportError(null);
    try {
      const res = await apiService.exportIncidentsCSV();
      const blob = new Blob([res.data], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `incidents_export_${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      setExportError(err?.response?.data?.detail || err?.message || 'CSV export failed');
    } finally {
      setExporting(false);
    }
  };

  return (
    <div>
      <div className="space-y-6 max-w-6xl mx-auto">

        {/* Back Button */}
        <button
          onClick={() => navigate('/dashboard')}
          className="flex items-center gap-2 text-xs tracking-widest uppercase transition-colors"
          style={{ color: '#6b7280' }}
          onMouseEnter={e => (e.currentTarget.style.color = '#9ca3af')}
          onMouseLeave={e => (e.currentTarget.style.color = '#6b7280')}
        >
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </button>

        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: '#d1d5db' }}>
              Incidents
            </h1>
            <p className="text-sm mt-1" style={{ color: '#6b7280' }}>
              {incidents.length} monitored alerts · {incidents.filter(i => i.status === 'OPEN').length} requiring immediate triaging
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleRetry}
              disabled={retrying || loading}
              className="flex items-center gap-2 px-3 py-1.5 rounded text-sm tracking-widest uppercase border transition-colors disabled:opacity-40"
              style={{ color: '#9ca3af', borderColor: '#333' }}
              onMouseEnter={e => { e.currentTarget.style.color = '#d1d5db'; e.currentTarget.style.borderColor = '#555'; }}
              onMouseLeave={e => { e.currentTarget.style.color = '#9ca3af'; e.currentTarget.style.borderColor = '#333'; }}
            >
              {retrying || loading ? 'Syncing...' : 'Refresh'}
            </button>
            <button
              onClick={handleExportCSV}
              disabled={exporting}
              className="flex items-center gap-2 px-3 py-1.5 rounded text-sm tracking-widest uppercase border transition-colors disabled:opacity-40"
              style={{ color: '#9ca3af', borderColor: '#333' }}
              onMouseEnter={e => { e.currentTarget.style.color = '#d1d5db'; e.currentTarget.style.borderColor = '#555'; }}
              onMouseLeave={e => { e.currentTarget.style.color = '#9ca3af'; e.currentTarget.style.borderColor = '#333'; }}
            >
              <Download className="w-3.5 h-3.5" /> {exporting ? 'Exporting...' : 'Export CSV'}
            </button>
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2" style={{ color: '#6b7280' }} />
              <input
                type="text"
                placeholder="Search..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="text-sm rounded px-2 py-1 pl-9 w-56"
                style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
              />
            </div>
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value as any)}
              className="text-sm rounded px-2 py-1 w-36"
              style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
            >
              <option value="all">All</option>
              <option value="OPEN">Open</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </div>
        </div>

        {incidentsError && (
          <div className="rounded-lg px-4 py-3 text-sm flex items-center justify-between" style={{ background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)', color: '#ff2d55' }}>
            <span>{incidentsError}</span>
            <button onClick={handleRetry} disabled={retrying} className="text-xs font-bold px-3 py-1 rounded ml-4 disabled:opacity-40" style={{ border: '1px solid rgba(255,45,85,0.4)', color: '#ff2d55' }}>
              {retrying ? 'Retrying...' : 'Retry'}
            </button>
          </div>
        )}

        {exportError && (
          <div className="rounded-lg px-4 py-3 text-sm flex items-center justify-between" style={{ background: 'rgba(255,149,0,0.1)', border: '1px solid rgba(255,149,0,0.3)', color: '#ff9500' }}>
            <span>Export: {exportError}</span>
            <button onClick={() => setExportError(null)} className="text-xs font-bold px-3 py-1 rounded ml-4" style={{ border: '1px solid rgba(255,149,0,0.4)', color: '#ff9500' }}>
              Dismiss
            </button>
          </div>
        )}

        {loading && incidents.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16 gap-4">
            <div className="w-8 h-8 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: '#333', borderTopColor: '#60a5fa' }} />
            <p className="text-sm" style={{ color: '#6b7280' }}>Loading incidents...</p>
            <button onClick={handleRetry} disabled={retrying} className="text-xs font-bold px-4 py-1.5 rounded disabled:opacity-40" style={{ border: '1px solid #333', color: '#9ca3af' }}>
              {retrying ? 'Retrying...' : 'Retry'}
            </button>
          </div>
        )}

        {/* Incidents List */}
        <div className="grid gap-3">
          {filteredIncidents.length === 0 && !loading ? (
            <div className="p-16 text-center rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px dashed rgba(75,85,99,0.2)' }}>
              <p className="text-sm" style={{ color: '#6b7280' }}>No incidents match current filters</p>
            </div>
          ) : (
            filteredIncidents.map((incident) => {
              const s = statusStyle[incident.status] || statusStyle.OPEN;
              const isInvestigating = investigatingId === incident.incident_id;
              const hasResult = !!investigationResults[incident.incident_id];
              return (
                <div
                  key={incident.incident_id}
                  className="p-5 rounded-lg cursor-pointer transition-all duration-200 group"
                  style={{
                    background: 'rgba(255,255,255,0.03)',
                    border: '1px solid ' + (incident.risk_score >= 70 ? 'rgba(255,45,85,0.2)' : 'rgba(75,85,99,0.2)'),
                  }}
                  onClick={() => {
                    setActivePanel(incident);
                    if (!incident.investigation_results && !hasResult && !isInvestigating) {
                      handleInvestigate(incident);
                    }
                  }}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2 flex-wrap">
                        <span className="text-sm font-bold px-2 py-0.5 rounded" style={{ background: s.bg, color: s.color, border: `1px solid ${s.color}33` }}>
                          {incident.status}
                        </span>
                        <span className="text-xs font-bold font-mono px-2 py-0.5 rounded" style={{
                          background: `${riskColor(incident.risk_score)}15`,
                          color: riskColor(incident.risk_score),
                          border: `1px solid ${riskColor(incident.risk_score)}33`
                        }}>
                          RISK {incident.risk_score}/100 · {riskLabel(incident.risk_score)}
                        </span>
                        {incident.risk_score < 40 && (
                          <span className="text-xs font-bold px-2 py-0.5 rounded" title="Score < 40: low-fidelity noise, safe to auto-filter after allowlist check" style={{ background: 'rgba(156,163,175,0.12)', color: '#9ca3af', border: '1px solid rgba(156,163,175,0.35)' }}>
                            LIKELY FP — AUTO-FILTERABLE
                          </span>
                        )}
                      </div>

                      <h3 className="font-bold text-base mb-1" style={{ color: '#d1d5db' }}>
                        {incident.description}
                      </h3>
                      <div className="flex gap-4 text-sm" style={{ color: '#6b7280' }}>
                        <span className="font-mono">ID: {incident.incident_id.slice(0, 8)}…</span>
                        <span>{((incident as { log_count?: number }).log_count ?? incident.source_logs?.length ?? 0)} correlation point(s)</span>
                        <span>{new Date(incident.timestamp).toLocaleString()}</span>
                      </div>

                      {hasResult && incident.status !== 'RESOLVED' && (
                        <div className="mt-3 flex gap-2">
                          {investigationResults[incident.incident_id].follow_up_steps?.slice(0, 2).map((_, i) => (
                            <div key={i} className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: '#22c55e' }} />
                          ))}
                          <span className="text-xs font-bold uppercase tracking-wider" style={{ color: '#22c55e' }}>
                            Next Steps Generated
                          </span>
                        </div>
                      )}
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={(e) => handleAskAi(incident, e)}
                        title="Open this incident in Chael AI for full live analysis"
                        className="text-sm px-3 py-1.5 rounded font-bold flex items-center gap-1.5"
                        style={{ border: '1px solid rgba(168,85,247,0.35)', color: '#a78bfa', background: 'rgba(168,85,247,0.08)' }}
                      >
                        <Bot className="w-3 h-3" />
                        Ask AI
                      </button>
                      <button
                        disabled={externalHuntLoading === incident.incident_id}
                        onClick={(e) => handleExternalHunt(incident, e)}
                        className="text-sm px-3 py-1.5 rounded font-bold disabled:opacity-40 flex items-center gap-1.5"
                        style={{ border: '1px solid rgba(96,165,250,0.3)', color: '#60a5fa', background: 'rgba(96,165,250,0.08)' }}
                      >
                        <Globe className="w-3 h-3" />
                        {externalHuntLoading === incident.incident_id ? 'Hunting...' : 'Hunt External'}
                      </button>
                      <button
                        disabled={isInvestigating}
                        onClick={(e) => handleInvestigate(incident, e)}
                        className="text-sm px-3 py-1.5 rounded font-bold disabled:opacity-40"
                        style={hasResult ? { border: '1px solid rgba(34,197,94,0.35)', color: '#22c55e', background: 'rgba(34,197,94,0.08)' } : { border: '1px solid #333', color: '#9ca3af' }}
                      >
                        {isInvestigating ? 'Triaging...' : hasResult ? 'View Roadmap' : 'Investigate'}
                      </button>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Investigation Panel Modal */}
      {activePanel && (
        <InvestigationPanel
          incident={activePanel}
          result={investigationResults[activePanel.incident_id] ?? activePanel.investigation_results ?? null}
          error={investigationError[activePanel.incident_id] ?? null}
          onRetry={() => handleInvestigate(activePanel)}
          onResolve={() => handleResolve(activePanel.incident_id)}
          onMitigate={handleMitigate}
          onClose={() => setActivePanel(null)}
        />
      )}

      {/* External Hunt Results Modal */}
      {activeExternalHunt && (
        <ExternalHuntPanel
          incident={incidents.find(i => i.incident_id === activeExternalHunt)!}
          result={externalHuntResults[activeExternalHunt] ?? null}
          error={externalHuntError[activeExternalHunt] ?? null}
          loading={externalHuntLoading === activeExternalHunt}
          onRetry={() => handleExternalHunt(incidents.find(i => i.incident_id === activeExternalHunt)!)}
          onClose={() => { setActiveExternalHunt(null); }}
        />
      )}
    </div>
  );
}

function ExternalHuntPanel({ incident, result, error, loading, onRetry, onClose }: {
  incident: Incident;
  result: any;
  error: string | null;
  loading: boolean;
  onRetry: () => void;
  onClose: () => void;
}) {
  const enrichData = result?.external_intel;
  const hasData = result?.found && enrichData && Object.keys(enrichData).length > 0;
  const sourcesLive: string[] = result?.sources_live || [];
  const confirmNote: string | undefined = result?.confirm_note;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(10,10,10,0.9)', backdropFilter: 'blur(6px)' }}>
      <div className="relative w-full max-w-3xl max-h-[85vh] overflow-hidden rounded-lg flex flex-col"
        style={{ background: '#0a0a0a', border: '1px solid rgba(75,85,99,0.2)' }}>
        {/* Header */}
        <div className="px-6 py-5 flex items-center justify-between shrink-0"
          style={{ background: '#0a0a0a', borderBottom: '1px solid rgba(75,85,99,0.2)' }}>
          <div className="flex items-center gap-4">
            <div className="p-2 rounded" style={{ background: 'rgba(96,165,250,0.1)' }}>
              <Globe className="w-6 h-6" style={{ color: '#60a5fa' }} />
            </div>
            <div>
              <span className="font-bold text-sm uppercase block" style={{ color: '#d1d5db' }}>
                External Threat Hunt
              </span>
              <span className="text-xs" style={{ color: '#6b7280' }}>{incident.incident_id}</span>
            </div>
          </div>
          <button onClick={onClose} className="p-2 rounded transition-colors" style={{ color: '#6b7280' }}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.05)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}>
            <X className="w-6 h-6" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-8 space-y-8 custom-scrollbar">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-24 space-y-6">
              <div className="w-8 h-8 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: '#333', borderTopColor: '#60a5fa' }} />
              <p className="text-xs uppercase" style={{ color: '#6b7280' }}>Querying external threat intelligence sources...</p>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center py-20 space-y-6">
              <div className="p-4 rounded-full" style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)' }}>
                <AlertTriangle className="w-12 h-12" style={{ color: '#ff2d55' }} />
              </div>
              <p className="text-sm text-center max-w-md" style={{ color: '#ff2d55' }}>{error}</p>
              <button onClick={onRetry} className="text-xs font-bold uppercase tracking-widest px-8 py-2 rounded" style={{ border: '1px solid #333', color: '#9ca3af' }}>
                Retry
              </button>
            </div>
          ) : !hasData ? (
            <div className="flex flex-col items-center justify-center py-20 space-y-4">
              <div className="p-4 rounded-full" style={{ background: 'rgba(107,114,128,0.1)', border: '1px solid rgba(107,114,128,0.2)' }}>
                <Shield className="w-12 h-12" style={{ color: '#6b7280' }} />
              </div>
              <p className="text-base font-bold" style={{ color: '#6b7280' }}>No External Threat Data</p>
              <p className="text-xs text-center max-w-md" style={{ color: '#6b7280' }}>
                No threat intelligence was found for the IOCs in this incident from external sources.
                {sourcesLive.length > 0
                  ? ` Sources checked live: ${sourcesLive.join(', ')}. Indicators appear unknown to those feeds — verify manually on the Hunt page.`
                  : ' No keyed-source keys are configured — free sources (ip-api, InternetDB, NVD, CVEDB) were checked live.'}
              </p>
              {confirmNote && (
                <p className="text-xs text-center max-w-md italic" style={{ color: '#6b7280' }}>{confirmNote}</p>
              )}
            </div>
          ) : (
            <>
              {/* Source status bar */}
              {(sourcesLive.length > 0 || confirmNote) && (
                <div className="p-3 rounded text-xs" style={{ background: 'rgba(96,165,250,0.06)', border: '1px solid rgba(96,165,250,0.2)', color: '#9ca3af' }}>
                  {sourcesLive.length > 0 && (
                    <div><span className="font-bold uppercase" style={{ color: '#60a5fa' }}>Sources live: </span><span className="font-mono">{sourcesLive.join(', ')}</span></div>
                  )}
                  {confirmNote && <div className="mt-1 italic">{confirmNote}</div>}
                </div>
              )}
              {/* IOC Summary */}
              {result?.iocs_extracted && (
                <div className="space-y-4">
                  <div className="flex items-center gap-3">
                    <Hash className="w-5 h-5" style={{ color: '#60a5fa' }} />
                    <span className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Extracted IOCs</span>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {result.iocs_extracted.ip_addresses?.length > 0 && (
                      <div className="p-3 rounded" style={{ background: 'rgba(96,165,250,0.08)', border: '1px solid rgba(96,165,250,0.2)' }}>
                        <span className="text-xs uppercase font-bold block mb-1" style={{ color: '#6b7280' }}>IP Addresses</span>
                        {result.iocs_extracted.ip_addresses.map((ip: string, i: number) => (
                          <span key={i} className="text-xs font-mono block" style={{ color: '#60a5fa' }}>{ip}</span>
                        ))}
                      </div>
                    )}
                    {result.iocs_extracted.cve_ids?.length > 0 && (
                      <div className="p-3 rounded" style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
                        <span className="text-xs uppercase font-bold block mb-1" style={{ color: '#6b7280' }}>CVEs</span>
                        {result.iocs_extracted.cve_ids.map((cve: string, i: number) => (
                          <a key={i} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer"
                            className="text-xs font-mono block hover:underline" style={{ color: '#ef4444' }}>{cve}</a>
                        ))}
                      </div>
                    )}
                    {result.iocs_extracted.hashes?.length > 0 && (
                      <div className="p-3 rounded" style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)' }}>
                        <span className="text-xs uppercase font-bold block mb-1" style={{ color: '#6b7280' }}>Hashes</span>
                        {result.iocs_extracted.hashes.map((h: string, i: number) => (
                          <span key={i} className="text-xs font-mono block truncate" style={{ color: '#f59e0b' }}>{h.slice(0, 20)}...</span>
                        ))}
                      </div>
                    )}
                    {result.iocs_extracted.domains?.length > 0 && (
                      <div className="p-3 rounded" style={{ background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)' }}>
                        <span className="text-xs uppercase font-bold block mb-1" style={{ color: '#6b7280' }}>Domains</span>
                        {result.iocs_extracted.domains.map((d: string, i: number) => (
                          <span key={i} className="text-xs font-mono block" style={{ color: '#22c55e' }}>{d}</span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* External Intel Results */}
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <Shield className="w-5 h-5" style={{ color: '#22c55e' }} />
                  <span className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>External Intelligence</span>
                  <span className="text-xs px-2 py-0.5 rounded" style={{ background: 'rgba(34,197,94,0.1)', color: '#22c55e' }}>Verified</span>
                </div>
                <div className="space-y-3">
                  {Object.entries(enrichData).map(([key, val]: [string, any]) => {
                    const sourceKey = Object.keys(val).find(k => k !== 'geoip' && k !== 'routability') || Object.keys(val)[0];
                    const sourceLabel = sourceKey || 'unknown';
                    const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(key);
                    const isCve = /^CVE-\d{4}-\d+$/i.test(key);
                    return (
                      <div key={key} className="p-4 rounded" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
                        <div className="flex items-center justify-between mb-3">
                          <span className="text-xs font-mono font-bold" style={{ color: '#d1d5db' }}>{key}</span>
                          <span className="text-xs uppercase px-2 py-0.5 rounded font-bold" style={{ background: 'rgba(96,165,250,0.1)', color: '#60a5fa' }}>
                            {sourceLabel}
                          </span>
                        </div>
                        {val.routability && (
                          <div className="mb-3 p-3 rounded text-xs" style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.3)', color: '#d1d5db' }}>
                            <span className="font-bold uppercase" style={{ color: '#f59e0b' }}>Not trackable externally — {val.routability.class}. </span>
                            <span style={{ color: '#9ca3af' }}>{val.routability.note}</span>
                          </div>
                        )}
                        <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
                          {val.virustotal && (
                            <>
                              <div><span style={{ color: '#6b7280' }}>Malicious:</span> <span className="text-red-400">{val.virustotal.malicious}</span></div>
                              <div><span style={{ color: '#6b7280' }}>Suspicious:</span> <span className="text-orange-400">{val.virustotal.suspicious}</span></div>
                              <div><span style={{ color: '#6b7280' }}>Reputation:</span> <span style={{ color: '#d1d5db' }}>{val.virustotal.reputation}</span></div>
                              {val.virustotal.country && <div><span style={{ color: '#6b7280' }}>Country:</span> <span style={{ color: '#d1d5db' }}>{val.virustotal.country}</span></div>}
                              {val.virustotal.as_owner && <div><span style={{ color: '#6b7280' }}>AS Owner:</span> <span style={{ color: '#d1d5db' }}>{val.virustotal.as_owner}</span></div>}
                            </>
                          )}
                          {val.abuseipdb && (
                            <>
                              <div><span style={{ color: '#6b7280' }}>Abuse Confidence:</span>{' '}
                                <span className={val.abuseipdb.abuse_confidence_score > 50 ? 'text-red-400' : 'text-green-400'}>
                                  {val.abuseipdb.abuse_confidence_score}%
                                </span>
                              </div>
                              <div><span style={{ color: '#6b7280' }}>Reports:</span> <span style={{ color: '#d1d5db' }}>{val.abuseipdb.total_reports}</span></div>
                              {val.abuseipdb.isp && <div><span style={{ color: '#6b7280' }}>ISP:</span> <span style={{ color: '#d1d5db' }}>{val.abuseipdb.isp}</span></div>}
                              {val.abuseipdb.usage_type && <div><span style={{ color: '#6b7280' }}>Usage:</span> <span style={{ color: '#d1d5db' }}>{val.abuseipdb.usage_type}</span></div>}
                            </>
                          )}
                          {val.shodan && (
                            <>
                              {val.shodan.ports?.length > 0 && <div><span style={{ color: '#6b7280' }}>Open Ports:</span> <span style={{ color: '#d1d5db' }}>{val.shodan.ports.join(', ')}</span></div>}
                              {val.shodan.vulns?.length > 0 && <div><span style={{ color: '#6b7280' }}>Vulns:</span> <span className="text-red-400">{val.shodan.vulns.join(', ')}</span></div>}
                              {val.shodan.os && <div><span style={{ color: '#6b7280' }}>OS:</span> <span style={{ color: '#d1d5db' }}>{val.shodan.os}</span></div>}
                            </>
                          )}
                          {val.greynoise && (
                            <>
                              <div><span style={{ color: '#6b7280' }}>Classification:</span>{' '}
                                <span className={val.greynoise.classification === 'malicious' ? 'text-red-400' : 'text-green-400'}>
                                  {val.greynoise.classification}
                                </span>
                              </div>
                              {val.greynoise.noise !== undefined && <div><span style={{ color: '#6b7280' }}>Noise:</span> <span style={{ color: '#d1d5db' }}>{String(val.greynoise.noise)}</span></div>}
                            </>
                          )}
                          {val.ipinfo && (
                            <>
                              {val.ipinfo.city && <div><span style={{ color: '#6b7280' }}>City:</span> <span style={{ color: '#d1d5db' }}>{val.ipinfo.city}</span></div>}
                              {val.ipinfo.country && <div><span style={{ color: '#6b7280' }}>Country:</span> <span style={{ color: '#d1d5db' }}>{val.ipinfo.country}</span></div>}
                              {val.ipinfo.org && <div><span style={{ color: '#6b7280' }}>Org:</span> <span style={{ color: '#d1d5db' }}>{val.ipinfo.org}</span></div>}
                            </>
                          )}
                          {val.geoip && (
                            <>
                              <div><span style={{ color: '#6b7280' }}>Location:</span> <span style={{ color: '#d1d5db' }}>{[val.geoip.city, val.geoip.country].filter(Boolean).join(', ')}</span></div>
                              {val.geoip.isp && <div><span style={{ color: '#6b7280' }}>ISP:</span> <span style={{ color: '#d1d5db' }}>{val.geoip.isp}</span></div>}
                              {val.geoip.asn && <div><span style={{ color: '#6b7280' }}>ASN:</span> <span style={{ color: '#d1d5db' }}>{val.geoip.asn}</span></div>}
                            </>
                          )}
                          {val.nvd && (
                            <>
                              <div><span style={{ color: '#6b7280' }}>Score:</span> <span className="text-red-400">{val.nvd.base_score}</span></div>
                              <div><span style={{ color: '#6b7280' }}>Severity:</span> <span style={{ color: '#d1d5db' }}>{val.nvd.severity}</span></div>
                              {val.nvd.attack_vector && <div><span style={{ color: '#6b7280' }}>Vector:</span> <span style={{ color: '#d1d5db' }}>{val.nvd.attack_vector}</span></div>}
                            </>
                          )}
                          {val.cvedb && (
                            <>
                              <div><span style={{ color: '#6b7280' }}>CVSS:</span> <span className="text-red-400">{val.cvedb.cvss}</span></div>
                              <div><span style={{ color: '#6b7280' }}>EPSS:</span> <span style={{ color: '#d1d5db' }}>{val.cvedb.epss}</span></div>
                              <div><span style={{ color: '#6b7280' }}>KEV:</span> <span style={{ color: val.cvedb.kev ? '#ff2d55' : '#22c55e' }}>{val.cvedb.kev ? 'YES — known exploited' : 'no'}</span></div>
                              {val.cvedb.ransomware_campaign && <div><span style={{ color: '#6b7280' }}>Ransomware:</span> <span className="text-red-400">{val.cvedb.ransomware_campaign}</span></div>}
                            </>
                          )}
                          {val.internetdb && (val.internetdb.ports?.length > 0 || val.internetdb.vulns?.length > 0 || val.internetdb.hostnames?.length > 0) && (
                            <>
                              {val.internetdb.ports?.length > 0 && <div><span style={{ color: '#6b7280' }}>Exposure (InternetDB):</span> <span style={{ color: '#d1d5db' }}>ports {val.internetdb.ports.join(', ')}</span></div>}
                              {val.internetdb.vulns?.length > 0 && <div><span style={{ color: '#6b7280' }}>Vulns:</span> <span className="text-red-400">{val.internetdb.vulns.join(', ')}</span></div>}
                              {val.internetdb.hostnames?.length > 0 && <div><span style={{ color: '#6b7280' }}>Hostnames:</span> <span style={{ color: '#d1d5db' }}>{val.internetdb.hostnames.slice(0, 3).join(', ')}</span></div>}
                            </>
                          )}
                          {val.otx && (
                            <>
                              <div><span style={{ color: '#6b7280' }}>Pulses:</span> <span style={{ color: '#d1d5db' }}>{val.otx.pulse_count}</span></div>
                              {val.otx.reputation !== undefined && <div><span style={{ color: '#6b7280' }}>Reputation:</span> <span style={{ color: '#d1d5db' }}>{val.otx.reputation}</span></div>}
                            </>
                          )}
                        </div>
                        <div className="mt-3 flex gap-4 flex-wrap">
                          {isIp && (
                            <>
                              <a href={`https://www.virustotal.com/gui/ip-address/${key}`} target="_blank" rel="noopener noreferrer"
                                className="text-xs flex items-center gap-1 hover:underline" style={{ color: '#60a5fa' }}>
                                <ExternalLink className="w-2.5 h-2.5" /> VirusTotal
                              </a>
                              <a href={`https://www.abuseipdb.com/check/${key}`} target="_blank" rel="noopener noreferrer"
                                className="text-xs flex items-center gap-1 hover:underline" style={{ color: '#60a5fa' }}>
                                <ExternalLink className="w-2.5 h-2.5" /> AbuseIPDB
                              </a>
                              <a href={`https://www.shodan.io/host/${key}`} target="_blank" rel="noopener noreferrer"
                                className="text-xs flex items-center gap-1 hover:underline" style={{ color: '#60a5fa' }}>
                                <ExternalLink className="w-2.5 h-2.5" /> Shodan
                              </a>
                              <a href={`https://viz.greynoise.io/riot/${key}`} target="_blank" rel="noopener noreferrer"
                                className="text-xs flex items-center gap-1 hover:underline" style={{ color: '#60a5fa' }}>
                                <ExternalLink className="w-2.5 h-2.5" /> GreyNoise
                              </a>
                            </>
                          )}
                          {isCve && (
                            <a href={`https://nvd.nist.gov/vuln/detail/${key.toUpperCase()}`} target="_blank" rel="noopener noreferrer"
                              className="text-xs flex items-center gap-1 hover:underline" style={{ color: '#60a5fa' }}>
                              <ExternalLink className="w-2.5 h-2.5" /> NVD
                            </a>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
