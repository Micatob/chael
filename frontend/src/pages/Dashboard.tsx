import React, { useEffect, useState, useMemo, lazy, Suspense } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLogStore } from '../stores';
import { useIncidentStore } from '../stores';
import { apiService } from '../services/api';
import { wsService } from '../services/websocket';
import { NormalizedLog, Incident } from '../types';

const ReactECharts = lazy(() => import('echarts-for-react'));

const GUIDANCE = [
  { id: 'deploy-agent', icon: '[+]', title: 'Deploy an Agent', desc: 'Install the Chael SIEM agent on endpoints to collect logs and security events.', action: '/agents', btn: 'Go to Agents' },
  { id: 'gen-key', icon: '[key]', title: 'Generate Enrollment Key', desc: 'Create a one-time enrollment key for secure agent deployment.', action: '/agents', btn: 'Generate Key' },
  { id: 'view-incidents', icon: '[!]', title: 'Investigate Active Incidents', desc: 'Review and respond to active security incidents detected by correlation rules.', action: '/incidents', btn: 'View Incidents' },
  { id: 'correlation-rules', icon: '[#]', title: 'Configure Correlation Rules', desc: 'Enable/disable detection rules and adjust thresholds for your environment.', action: '/soar', btn: 'Configure Rules' },
  { id: 'threat-hunt', icon: '[~]', title: 'Run a Threat Hunt', desc: 'Use the threat hunting interface to search for incidents and indicators of compromise.', action: '/hunt', btn: 'Start Hunt' },
  { id: 'soar-config', icon: '[>]', title: 'Configure SOAR Playbooks', desc: 'Set up automated response actions for brute force, critical incidents, and more.', action: '/soar', btn: 'Configure' },
  { id: 'yara-scans', icon: '[y]', title: 'Review YARA Scan Results', desc: 'Check YARA rule matches for malware indicators on endpoints.', action: '/yara', btn: 'View YARA' },
  { id: 'threat-feeds', icon: '[i]', title: 'Configure Threat Intelligence', desc: 'Connect to AlienVault OTX or upload custom IoC feeds.', action: '/threat-feed', btn: 'Configure' },
  { id: 'network-flows', icon: '[~]', title: 'Analyze Network Flows', desc: 'Review NetFlow data for unusual connections and data exfiltration.', action: '/flows', btn: 'View Flows' },
  { id: 'ml-analytics', icon: '[%]', title: 'Review ML Analytics', desc: 'Check UEBA anomalies and behavioral analytics for insider threats.', action: '/analytics', btn: 'View Analytics' },
  { id: 'set-notifications', icon: '[!]', title: 'Configure Notifications', desc: 'Set up alert notifications for critical security events.', action: '/soar', btn: 'Configure' },
];

interface GuidanceItem {
  id: string; icon: string; title: string; desc: string; action: string; btn: string;
}

function getContextualGuidance(incidents: Incident[], rules: any[], logs: NormalizedLog[]): GuidanceItem[] {
  const suggestions: GuidanceItem[] = [];
  const activeIncidents = incidents.filter(i => i.status === 'OPEN' || i.status === 'INVESTIGATING');
  const hasCritical = incidents.some(i => i.risk_score >= 90 && i.status !== 'RESOLVED');
  const highIncidents = incidents.filter(i => i.risk_score >= 70 && i.status !== 'RESOLVED');

  if (activeIncidents.length > 0) {
    suggestions.push({ ...GUIDANCE.find(g => g.id === 'view-incidents')!, desc: `${activeIncidents.length} incident(s) need investigation. High risk: ${highIncidents.length}` });
  }
  if (hasCritical) {
    suggestions.push({ ...GUIDANCE.find(g => g.id === 'threat-hunt')!, desc: 'Critical threats detected — hunt for related incidents across your environment.' });
  }
  if (logs.length < 5) {
    suggestions.push({ ...GUIDANCE.find(g => g.id === 'deploy-agent')!, desc: 'No log data detected. Deploy an agent on a Windows/Linux endpoint to start collecting.' });
  }
  if (rules.length === 0) {
    suggestions.push({ ...GUIDANCE.find(g => g.id === 'correlation-rules')!, desc: 'No correlation rules loaded — detection is disabled. Enable or create rules.' });
  }
  const hasDisabledRules = rules.filter(r => !r.enabled).length > 0;
  if (hasDisabledRules) {
    suggestions.push({ ...GUIDANCE.find(g => g.id === 'correlation-rules')!, desc: `${rules.filter(r => !r.enabled).length} rule(s) disabled below — enable them for full coverage.` });
  }
  if (activeIncidents.length === 0 && logs.length > 5) {
    suggestions.push({ ...GUIDANCE.find(g => g.id === 'threat-hunt')!, desc: 'No active incidents — proactively hunt for threats in your environment.' });
  }
  if (suggestions.length < 3) {
    suggestions.push(GUIDANCE.find(g => g.id === 'soar-config')!);
    suggestions.push(GUIDANCE.find(g => g.id === 'set-notifications')!);
  }
  return suggestions.slice(0, 4);
}

function GuidancePanel({ items, navigate }: { items: GuidanceItem[]; navigate: ReturnType<typeof useNavigate> }) {
  if (items.length === 0) return null;
  const handleAction = (action: string) => {
    if (action.startsWith('#')) {
      const el = document.getElementById(action.slice(1));
      if (el) el.scrollIntoView({ behavior: 'smooth' });
    } else {
      navigate(action);
    }
  };
  return (
    <div className="p-4 rounded" style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(75,85,99,0.3)' }}>
      <div className="text-sm font-bold mb-3 uppercase tracking-wider" style={{ color: '#9ca3af' }}>Suggestions</div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        {items.map((item) => (
          <div
            key={item.id}
            className="rounded p-3 cursor-pointer"
            style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}
            onClick={() => handleAction(item.action)}
          >
            <div className="flex items-start gap-2">
              <span className="text-xs font-mono shrink-0 mt-0.5" style={{ color: '#60a5fa' }}>{item.icon}</span>
              <div className="min-w-0">
                <div className="text-base font-semibold" style={{ color: '#d1d5db' }}>{item.title}</div>
                <p className="text-sm mt-0.5" style={{ color: '#6b7280' }}>{item.desc}</p>
                <span className="inline-block mt-1 text-xs uppercase" style={{ color: '#9ca3af' }}>
                  {item.btn}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ChartSkeleton() {
  return <div className="h-[280px] rounded-lg animate-pulse" style={{ background: 'rgba(0,212,255,0.03)' }} />;
}

const Dashboard: React.FC = () => {
  const { logs, error: logsError, setLogs } = useLogStore();
  const { incidents, error: incidentsError, setIncidents } = useIncidentStore();
  const [expandedLog, setExpandedLog] = useState<NormalizedLog | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [analyticsOverview, setAnalyticsOverview] = useState<any>(null);
  const [soarHistory, setSoarHistory] = useState<any[]>([]);
  const [guidanceItems, setGuidanceItems] = useState<GuidanceItem[]>([]);
  const [dataLoaded, setDataLoaded] = useState(false);
  const [agents, setAgents] = useState<Array<{ agent_id: string; hostname: string; last_seen: string; online: boolean }>>([]);
  const [sources, setSources] = useState<Array<{ hostname: string; status: string; timestamp: string }>>([]);
  const [agentError, setAgentError] = useState<string | null>(null);
  const [purgeError, setPurgeError] = useState<string | null>(null);
  const navigate = useNavigate();

  const searchLower = searchTerm.toLowerCase();
  const filteredLogs = useMemo(() => logs.filter(log =>
    log.message.toLowerCase().includes(searchLower) ||
    log.host.toLowerCase().includes(searchLower)
  ), [logs, searchLower]);

  const activeIncidents = incidents.filter(i => i.status === 'OPEN' || i.status === 'INVESTIGATING');
  const criticalCount = incidents.filter(i => i.risk_score >= 70 && i.status !== 'RESOLVED').length;

  useEffect(() => {
    fetchAll();
    const interval = setInterval(() => fetchAll(), 30000);
    const token = localStorage.getItem('s2_token');
    wsService.connect(token ?? undefined);
    const onAgent = () => fetchAgentsOnly();
    wsService.on('agent:status', onAgent);
    wsService.on('agent:heartbeat', onAgent);
    return () => {
      clearInterval(interval);
      wsService.off('agent:status', onAgent);
      wsService.off('agent:heartbeat', onAgent);
    };
  }, []);

  const fetchAgentsOnly = async () => {
    try {
      const [agentsRes, sourcesRes] = await Promise.allSettled([
        apiService.listAgents(),
        apiService.getLogSources(),
      ]);
      if (agentsRes.status === 'fulfilled') {
        setAgents(agentsRes.value.data || []);
        setAgentError(null);
      }
      if (sourcesRes.status === 'fulfilled') setSources(sourcesRes.value.data || []);
    } catch (e) {
      console.error('Agent refresh failed', e);
    }
  };

  const fetchAll = async () => {
    // Always show Syncing so manual Refresh gives visible feedback
    setIsRefreshing(true);
    try {
      const [logsResponse, incidentsResponse, overviewResponse, soarResponse, agentsResponse, sourcesResponse] = await Promise.allSettled([
        apiService.getLogs(50),
        apiService.getIncidents(),
        apiService.getAnalyticsOverview(),
        apiService.getSOARHistory(20),
        apiService.listAgents(),
        apiService.getLogSources(),
      ]);

      const logsData = logsResponse.status === 'fulfilled' ? logsResponse.value.data : [];
      const incidentsData = incidentsResponse.status === 'fulfilled' ? incidentsResponse.value.data : [];
      const overviewData = overviewResponse.status === 'fulfilled' ? overviewResponse.value.data : null;
      const soarData = soarResponse.status === 'fulfilled' ? soarResponse.value.data?.history : [];
      const agentsData = agentsResponse.status === 'fulfilled' ? agentsResponse.value.data : [];
      const sourcesData = sourcesResponse.status === 'fulfilled' ? sourcesResponse.value.data : [];

      setLogs(logsData);
      setIncidents(incidentsData);
      setAnalyticsOverview(overviewData);
      setSoarHistory(soarData || []);
      setAgents(agentsData || []);
      setSources(sourcesData || []);
      if (agentsResponse.status === 'rejected') {
        setAgentError('Agent service unreachable — showing last known fleet state');
      } else {
        setAgentError(null);
      }
      setGuidanceItems(getContextualGuidance(incidentsData, [], logsData));
      setDataLoaded(true);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
      setDataLoaded(true);
    } finally {
      setIsRefreshing(false);
    }
  };

  const refreshAll = async () => {
    await fetchAll();
  };

  const handleLogout = () => {
    localStorage.removeItem('s2_token');
    window.dispatchEvent(new Event('authchange'));
    navigate('/login');
  };

  // Ingestion Velocity area chart
  const ingestionChartOption = useMemo(() => analyticsOverview ? {
    tooltip: { trigger: 'axis' as const },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category' as const,
      data: analyticsOverview.ingestion_trend.map((t: any) => t.name),
      axisLine: { lineStyle: { color: '#4b5563' } },
      axisLabel: { color: '#9ca3af' },
    },
    yAxis: {
      type: 'value' as const,
      axisLine: { lineStyle: { color: '#4b5563' } },
      axisLabel: { color: '#9ca3af' },
      splitLine: { lineStyle: { color: '#374151' } },
    },
    series: [{
      data: analyticsOverview.ingestion_trend.map((t: any) => t.logs),
      type: 'line' as const,
      smooth: true,
      itemStyle: { color: '#00d4ff' },
      areaStyle: {
        color: {
          type: 'linear' as const,
          x: 0, y: 0, x2: 0, y2: 1,
          colorStops: [
            { offset: 0, color: 'rgba(0,212,255,0.3)' },
            { offset: 1, color: 'rgba(0,212,255,0.05)' },
          ],
        },
      },
    }],
  } : null, [analyticsOverview]);

  // Incident Severity donut chart
  const severityData = useMemo(() => incidents.reduce((acc: Record<string, number>, i: Incident) => {
    const sev = i.risk_score >= 90 ? 'CRITICAL' : i.risk_score >= 70 ? 'HIGH' : i.risk_score >= 50 ? 'MEDIUM' : 'LOW';
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {}), [incidents]);

  const severityColors: Record<string, string> = {
    CRITICAL: '#ff2d55',
    HIGH: '#ff9500',
    MEDIUM: '#ffcc02',
    LOW: '#30d158',
  };

  const severityChartOption = useMemo(() => ({
    tooltip: { trigger: 'item' as const, formatter: '{b}: {c} ({d}%)' },
    series: [{
      type: 'pie' as const,
      radius: ['45%', '70%'],
      avoidLabelOverlap: true,
      itemStyle: { borderRadius: 4, borderColor: '#0a0e1a', borderWidth: 2 },
      label: { color: '#9ca3af', fontSize: 11 },
      emphasis: { label: { fontSize: 14, fontWeight: 'bold' as const } },
      data: Object.entries(severityData).map(([name, value]) => ({
        name,
        value,
        itemStyle: { color: severityColors[name] || '#6b7280' },
      })),
    }],
  }), [severityData]);

  // Incidents by severity bar chart
  const barChartOption = useMemo(() => ({
    tooltip: { trigger: 'axis' as const },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category' as const,
      data: Object.keys(severityData),
      axisLine: { lineStyle: { color: '#4b5563' } },
      axisLabel: { color: '#9ca3af' },
    },
    yAxis: {
      type: 'value' as const,
      axisLine: { lineStyle: { color: '#4b5563' } },
      axisLabel: { color: '#9ca3af' },
      splitLine: { lineStyle: { color: '#374151' } },
    },
    series: [{
      type: 'bar' as const,
      data: Object.entries(severityData).map(([name, value]) => ({
        value,
        itemStyle: { color: severityColors[name] || '#6b7280', borderRadius: [4, 4, 0, 0] },
      })),
    }],
  }), [severityData]);

  // SOAR Action Success ring chart
  const soarChartOption = useMemo(() => {
    const soarStatusCounts = soarHistory.reduce((acc: Record<string, number>, a: any) => {
      acc[a.status] = (acc[a.status] || 0) + 1;
      return acc;
    }, {});
    return {
      tooltip: { trigger: 'item' as const, formatter: '{b}: {c} ({d}%)' },
      series: [{
        type: 'pie' as const,
        radius: ['60%', '80%'],
        avoidLabelOverlap: false,
        itemStyle: { borderRadius: 4, borderColor: '#0a0e1a', borderWidth: 2 },
        label: { color: '#9ca3af', fontSize: 11 },
        data: [
          { name: 'EXECUTED', value: soarStatusCounts['EXECUTED'] || 0, itemStyle: { color: '#30d158' } },
          { name: 'FAILED', value: soarStatusCounts['FAILED'] || 0, itemStyle: { color: '#ff2d55' } },
          { name: 'PENDING', value: soarStatusCounts['PENDING'] || 0, itemStyle: { color: '#ffcc02' } },
        ],
      }],
    };
  }, [soarHistory]);

  // Agent heartbeat / fleet health — live via listAgents + sources polling + WS
  const onlineCount = useMemo(() => agents.filter((a) => a.online).length, [agents]);
  const offlineCount = useMemo(() => agents.length - onlineCount, [agents, onlineCount]);
  const agentHeartbeatOption = useMemo(() => ({
    tooltip: { trigger: 'item' as const, formatter: '{b}: {c} ({d}%)' },
    series: [{
      type: 'pie' as const,
      radius: ['60%', '80%'],
      avoidLabelOverlap: false,
      itemStyle: { borderRadius: 4, borderColor: '#0a0e1a', borderWidth: 2 },
      label: { color: '#9ca3af', fontSize: 11 },
      data: [
        { name: 'ONLINE', value: onlineCount, itemStyle: { color: '#22c55e' } },
        { name: 'OFFLINE', value: offlineCount, itemStyle: { color: '#ef4444' } },
      ],
    }],
  }), [onlineCount, offlineCount]);

  if (!dataLoaded && logs.length === 0) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ background: '#0a0a0a' }}>
        <div className="text-center space-y-3">
          <div className="w-10 h-10 border-2 border-t-transparent rounded-full animate-spin mx-auto" style={{ borderColor: '#333', borderTopColor: '#60a5fa' }} />
          <p className="text-xs" style={{ color: '#6b7280' }}>Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="font-sans">

      {/* Top Bar */}
      <header className="border-b px-6 py-3 flex justify-between items-center sticky top-0 z-40"
        style={{ background: '#111', borderColor: '#333' }}>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold uppercase" style={{ color: '#d1d5db' }}>
              Chael SIEM
            </h1>
            <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ color: '#6b7280', border: '1px solid #333' }}>
              v1.0
            </span>
          </div>
          {(logsError || incidentsError) && (
            <div className="text-xs mt-1" style={{ color: '#ef4444' }}>
              Error: {logsError || incidentsError}
            </div>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={async () => {
              const { generateDashboardReport } = await import('../utils/reportGenerator');
              generateDashboardReport(logs, incidents, soarHistory, agents);
            }}
            className="text-xs px-3 py-1.5 rounded"
            style={{ border: '1px solid #333', color: '#9ca3af' }}
          >
            Export Report
          </button>
          <button
            onClick={() => navigate('/hunt')}
            className="text-xs px-3 py-1.5 rounded"
            style={{ border: '1px solid #333', color: '#9ca3af' }}
          >
            Threat Hunt
          </button>
          <button
            onClick={refreshAll}
            disabled={isRefreshing}
            className="text-xs px-3 py-1.5 rounded disabled:opacity-40"
            style={{ border: '1px solid #333', color: '#9ca3af' }}
          >
            {isRefreshing ? 'Syncing...' : 'Refresh'}
          </button>
          <button
            onClick={async () => {
              if (!window.confirm('Purge ALL telemetry data? Logs are always purged. Incidents under legal hold are kept and will block only the incident purge (SOAR audit history is preserved by design). This cannot be undone.')) return;
              setPurgeError(null);
              try {
                await apiService.purgeAllData();
                setLogs([]);
                setIncidents([]);
                setAnalyticsOverview(null);
                // NOTE: SOAR history lives in the tamper-evident audit index and
                // is intentionally never purged — do not clear it locally.
                setGuidanceItems([]);
                setDataLoaded(false);
                fetchAll();
              } catch (e: any) {
                const detail = e?.response?.data?.detail;
                const msg = typeof detail === 'string' ? detail
                  : detail?.message || 'Purge failed';
                const holds = (typeof detail === 'object' && detail?.hold_count)
                  ? ` (${detail.hold_count} incident(s) on legal hold kept — telemetry was still purged; release holds on the Incidents page to clear them).`
                  : '';
                setPurgeError(msg + holds);
                fetchAll();
              }
            }}
            className="text-xs px-3 py-1.5 rounded"
            style={{ border: '1px solid #7f1d1d', color: '#ef4444' }}
          >
            Purge Data
          </button>
          <button onClick={handleLogout} className="text-xs px-3 py-1.5 rounded"
            style={{ border: '1px solid #7f1d1d', color: '#ef4444' }}>
            Logout
          </button>
        </div>
      </header>

      {purgeError && (
        <div className="mx-6 mt-4 p-3 rounded text-sm" style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid #7f1d1d', color: '#fca5a5' }}>
          {purgeError}
          <button onClick={() => setPurgeError(null)} className="ml-3 underline">Dismiss</button>
        </div>
      )}

      <main className="p-6 space-y-6">

        <GuidancePanel items={guidanceItems} navigate={navigate} />

        {/* Stat Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div
            className="p-4 rounded cursor-pointer"
            style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}
            onClick={() => navigate('/logs')}
          >
            <div className="text-sm font-bold mb-1 uppercase" style={{ color: '#6b7280' }}>Logs</div>
            <div className="text-4xl font-bold font-mono" style={{ color: '#d1d5db' }}>{logs.length}</div>
            <div className="text-sm mt-1" style={{ color: '#6b7280' }}>ingested</div>
          </div>

          <div
            className="p-4 rounded cursor-pointer"
            style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}
            onClick={() => navigate('/incidents')}
          >
            <div className="text-sm font-bold mb-1 uppercase" style={{ color: '#6b7280' }}>Incidents</div>
            <div className="text-4xl font-bold font-mono" style={{ color: activeIncidents.length > 0 ? '#f59e0b' : '#d1d5db' }}>
              {activeIncidents.length}
            </div>
            <div className="text-sm mt-1" style={{ color: '#6b7280' }}>
              {activeIncidents.length > 0 ? 'active' : 'none'}
            </div>
          </div>

          <div className="p-4 rounded"
            style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
            <div className="text-sm font-bold mb-1 uppercase" style={{ color: '#6b7280' }}>Health</div>
            <div className="text-4xl font-bold font-mono" style={{ color: criticalCount > 0 ? '#ef4444' : '#22c55e' }}>
              {criticalCount > 0 ? 'ALERT' : 'OK'}
            </div>
            <div className="text-sm mt-1" style={{ color: '#6b7280' }}>
              {criticalCount > 0 ? `${criticalCount} critical` : 'operational'}
            </div>
          </div>

          <div className="p-4 rounded"
            style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
            <div className="text-sm font-bold mb-1 uppercase" style={{ color: '#6b7280' }}>24h Events</div>
            <div className="text-4xl font-bold font-mono" style={{ color: '#d1d5db' }}>
              {analyticsOverview?.total_logs_24h || 0}
            </div>
            <div className="text-sm mt-1" style={{ color: '#6b7280' }}>last 24 hours</div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="p-4 rounded" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
            <div className="text-sm font-bold mb-3 uppercase" style={{ color: '#6b7280' }}>Ingestion Velocity</div>
            <Suspense fallback={<ChartSkeleton />}>
              {ingestionChartOption && <ReactECharts option={ingestionChartOption} style={{ height: '280px' }} />}
            </Suspense>
          </div>
          <div className="p-4 rounded" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
            <div className="text-sm font-bold mb-3 uppercase" style={{ color: '#6b7280' }}>Incident Severity</div>
            <Suspense fallback={<ChartSkeleton />}>
              {severityChartOption && <ReactECharts option={severityChartOption} style={{ height: '280px' }} />}
            </Suspense>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="p-4 rounded" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
            <div className="text-sm font-bold mb-3 uppercase" style={{ color: '#6b7280' }}>Incidents Last 24h</div>
            <Suspense fallback={<ChartSkeleton />}>
              {barChartOption && <ReactECharts option={barChartOption} style={{ height: '280px' }} />}
            </Suspense>
          </div>
          <div className="p-4 rounded" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
            <div className="text-sm font-bold mb-3 uppercase" style={{ color: '#6b7280' }}>SOAR Actions</div>
            <Suspense fallback={<ChartSkeleton />}>
              {soarChartOption && <ReactECharts option={soarChartOption} style={{ height: '280px' }} />}
            </Suspense>
          </div>
        </div>

        {/* Agent Fleet Health — live heartbeat (polling 30s + WS agent:status) */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="p-4 rounded" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
            <div className="flex items-center justify-between mb-3">
              <div className="text-sm font-bold uppercase" style={{ color: '#6b7280' }}>
                Agent Heartbeat — {onlineCount} online / {offlineCount} offline · {agents.length} total
              </div>
              <button onClick={() => navigate('/agents')} className="text-xs px-2 py-1 rounded" style={{ border: '1px solid #333', color: '#9ca3af' }}>
                View Agents
              </button>
            </div>
            {agentError && <div className="text-xs mb-2" style={{ color: '#f59e0b' }}>{agentError}</div>}
            <Suspense fallback={<ChartSkeleton />}>
              <ReactECharts option={agentHeartbeatOption} style={{ height: '220px' }} />
            </Suspense>
            <div className="text-xs mt-2" style={{ color: '#6b7280' }}>
              {wsService.isConnected() ? 'Live: WebSocket connected' : 'Live: polling every 30s (WS backoff when gateway has no socket.io)'} · {sources.length} log source(s) reporting
            </div>
          </div>
          <div className="p-4 rounded" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
            <div className="text-sm font-bold mb-3 uppercase" style={{ color: '#6b7280' }}>Fleet — Last Seen</div>
            <div className="space-y-1 max-h-56 overflow-y-auto pr-1">
              {agents.length === 0 ? (
                <p className="text-center py-6 text-xs" style={{ color: '#6b7280' }}>No agents registered. Deploy an agent to start heartbeat.</p>
              ) : (
                agents.slice(0, 8).map((a) => (
                  <div key={a.agent_id} className="flex items-center justify-between px-3 py-2 rounded" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(75,85,99,0.15)' }}>
                    <span className="text-sm font-bold truncate" style={{ color: '#d1d5db' }}>{a.hostname}</span>
                    <span className="text-xs font-bold px-2 py-0.5 rounded" style={{
                      background: a.online ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)',
                      color: a.online ? '#22c55e' : '#ef4444',
                    }}>
                      {a.online ? 'ONLINE' : 'OFFLINE'}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Recent Logs + Active Incidents Row */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

          {/* Recent Logs */}
          <div className="p-4 rounded md:col-span-2" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
            <div className="flex items-center justify-between mb-3">
              <div className="text-sm font-bold uppercase" style={{ color: '#6b7280' }}>Recent Telemetry</div>
              <input
                type="text"
                placeholder="Filter..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="text-xs rounded px-2 py-1"
                style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db', width: '120px' }}
              />
            </div>
            <div className="space-y-1 max-h-72 overflow-y-auto pr-1">
              {logs.length === 0 ? (
                <p className="text-center py-6 text-xs" style={{ color: '#6b7280' }}>No logs ingested. Run ingest-sample.cjs</p>
              ) : (
                filteredLogs.slice(0, 8).map((log, index) => (
                  <div
                    key={log.timestamp + index}
                    className="rounded px-3 py-2 cursor-pointer"
                    style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(75,85,99,0.15)' }}
                    onClick={() => setExpandedLog(expandedLog === log ? null : log)}
                  >
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-bold" style={{ color: '#d1d5db' }}>{log.host}</span>
                      <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{
                        background: log.severity === 'CRITICAL' ? 'rgba(239,68,68,0.15)' : log.severity === 'HIGH' ? 'rgba(245,158,11,0.15)' : 'rgba(75,85,99,0.15)',
                        color: log.severity === 'CRITICAL' ? '#ef4444' : log.severity === 'HIGH' ? '#f59e0b' : '#9ca3af'
                      }}>{log.severity}</span>
                    </div>
                    <p className="text-sm mt-0.5 truncate" style={{ color: '#6b7280' }}>{log.message}</p>
                    {expandedLog === log && (
                      <div className="mt-2 pt-2" style={{ borderTop: '1px solid rgba(75,85,99,0.2)' }}>
                        <pre className="text-xs whitespace-pre-wrap overflow-x-auto" style={{ color: '#9ca3af' }}>
                          {JSON.stringify(log.metadata, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Active Incidents */}
          <div className="p-4 rounded" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
            <div className="text-sm font-bold mb-3 uppercase" style={{ color: '#6b7280' }}>Active Threats</div>
            <div className="space-y-1 max-h-72 overflow-y-auto pr-1">
              {activeIncidents.length === 0 ? (
                <p className="text-center py-6 text-xs" style={{ color: '#6b7280' }}>No active incidents</p>
              ) : (
                activeIncidents.slice(0, 5).map((incident) => (
                  <div
                    key={incident.incident_id}
                    className="rounded px-3 py-2 cursor-pointer"
                    style={{ background: 'rgba(245,158,11,0.04)', border: '1px solid rgba(245,158,11,0.15)' }}
                    onClick={() => navigate('/incidents')}
                  >
                    <div className="text-sm font-bold mb-1" style={{ color: '#d1d5db' }}>{incident.description}</div>
                    <div className="flex justify-between text-sm">
                      <span style={{ color: incident.risk_score >= 70 ? '#ef4444' : '#f59e0b' }}>
                        Risk: {incident.risk_score}
                      </span>
                      <span style={{ color: '#6b7280' }}>{incident.status}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Correlation Rules moved to SOAR page */}
      </main>
    </div>
  );
};

export default Dashboard;
