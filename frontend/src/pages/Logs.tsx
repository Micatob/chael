import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useLogs } from '../hooks';
import { Search, ArrowLeft, ChevronDown, ChevronUp } from 'lucide-react';
import { NormalizedLog } from '../types';

const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const severityStyle: Record<string, { color: string; bg: string; border: string }> = {
  CRITICAL: { color: '#ff2d55', bg: 'rgba(255,45,85,0.12)', border: 'rgba(255,45,85,0.3)' },
  HIGH:     { color: '#ff9500', bg: 'rgba(255,149,0,0.12)', border: 'rgba(255,149,0,0.3)' },
  MEDIUM:   { color: '#ffcc00', bg: 'rgba(255,204,0,0.1)',  border: 'rgba(255,204,0,0.3)' },
  LOW:      { color: '#30d158', bg: 'rgba(48,209,88,0.1)',  border: 'rgba(48,209,88,0.3)' },
  INFO:     { color: '#6b7280', bg: 'rgba(107,114,128,0.1)', border: 'rgba(107,114,128,0.2)' },
};

function LogRow({ log }: { log: NormalizedLog }) {
  const [expanded, setExpanded] = useState(false);
  const s = severityStyle[log.severity] || severityStyle.INFO;

  return (
    <>
      <tr
        className="transition-colors duration-100 cursor-pointer"
        style={{ borderBottom: '1px solid rgba(75,85,99,0.2)' }}
        onClick={() => setExpanded(!expanded)}
      >
        <td className="py-3 px-4 text-sm font-mono" style={{ color: '#6b7280' }}>
          {new Date(log.timestamp).toLocaleString()}
        </td>
        <td className="py-3 px-4 text-sm font-bold" style={{ color: '#d1d5db' }}>{log.host}</td>
        <td className="py-3 px-4 text-sm" style={{ color: '#6b7280' }}>{log.source}</td>
        <td className="py-3 px-4 text-sm uppercase tracking-wider" style={{ color: '#6b7280' }}>{log.log_type}</td>
        <td className="py-3 px-4">
          <span className="text-sm font-bold px-2 py-0.5 rounded" style={{ background: s.bg, color: s.color, border: `1px solid ${s.border}` }}>
            {log.severity}
          </span>
        </td>
        <td className="py-3 px-4 text-sm max-w-xs" style={{ color: '#d1d5db' }}>
          <div className="flex items-center gap-2">
            <span className="truncate">{log.message}</span>
            {expanded ? <ChevronUp className="w-3 h-3 shrink-0" style={{ color: '#6b7280' }} /> : <ChevronDown className="w-3 h-3 shrink-0" style={{ color: '#6b7280' }} />}
          </div>
        </td>
      </tr>
      {expanded && (
        <tr style={{ background: 'rgba(255,255,255,0.02)' }}>
          <td colSpan={6} className="px-8 py-4">
            <div className="text-sm font-bold uppercase mb-2" style={{ color: '#6b7280' }}>Message</div>
            <div className="text-sm mb-4 rounded p-3" style={{ color: '#d1d5db', background: '#1a1a1a', border: '1px solid rgba(96,165,250,0.15)' }}>
              {log.message || 'No message content'}
            </div>
            <div className="flex items-center gap-2 mb-4 text-xs">
              <span className="font-bold uppercase" style={{ color: '#6b7280' }}>Integrity</span>
              {(log.metadata as any)?.log_hash ? (
                <span className="font-mono" style={{ color: '#30d158' }}>
                  sealed {(log.metadata as any).log_hash.slice(0, 12)}…
                </span>
              ) : (
                <span style={{ color: '#ff9500' }}>unsealed (ingested before sealing)</span>
              )}
              {((log.metadata as any)?.forensics_only || (log.metadata as any)?.fp_internal) && (
                <span style={{ color: '#60a5fa' }}>· retained for forensics (below alert threshold)</span>
              )}
            </div>
            <div className="text-sm font-bold uppercase mb-2" style={{ color: '#6b7280' }}>Metadata</div>
            <pre className="text-sm rounded p-3" style={{ color: '#22c55e', background: '#1a1a1a', border: '1px solid rgba(34,197,94,0.1)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
              {JSON.stringify(log.metadata, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}

export function Logs() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { logs, loading, error, fetchLogs } = useLogs();
  const [search, setSearch] = useState(params.get('q') || '');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [hostFilter, setHostFilter] = useState<string>(params.get('host') || 'all');
  const [timeRange, setTimeRange] = useState<string>('all');
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const handleRefresh = async () => {
    await fetchLogs(100, 0);
  };

  const handleExport = async (format: 'json' | 'csv') => {
    setExporting(true);
    setExportError(null);
    try {
      const { apiService } = await import('../services/api');
      const res = await apiService.exportLogs(format);
      const payload = format === 'json' ? JSON.stringify(res.data, null, 2) : (res.data as any).csv || '';
      const blob = new Blob([payload], { type: format === 'json' ? 'application/json' : 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `chael_logs_${new Date().toISOString().slice(0, 10)}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      setExportError(e?.response?.data?.detail || e.message || 'Export failed');
    } finally {
      setExporting(false);
    }
  };

  const sources = [...new Set(logs.map((l) => l.source))];
  const hosts = [...new Set(logs.map((l) => l.host))];

  const timeCutoff = timeRange === '1h' ? Date.now() - 3600_000
    : timeRange === '24h' ? Date.now() - 86_400_000
    : timeRange === '7d' ? Date.now() - 7 * 86_400_000 : 0;

  const filteredLogs = logs.filter((log) => {
    const matchesSearch =
      log.message.toLowerCase().includes(search.toLowerCase()) ||
      log.host.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === 'all' || log.severity === severityFilter;
    const matchesSource = sourceFilter === 'all' || log.source === sourceFilter;
    const matchesHost = hostFilter === 'all' || log.host === hostFilter;
    const matchesTime = !timeCutoff || new Date(log.timestamp).getTime() >= timeCutoff;
    return matchesSearch && matchesSeverity && matchesSource && matchesHost && matchesTime;
  });

  const severityCounts = severityOrder.reduce((acc, sev) => {
    acc[sev] = logs.filter(l => l.severity === sev).length;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div>
      <div className="space-y-6 max-w-7xl mx-auto">

        {/* Back Button */}
        <button
          onClick={() => navigate('/dashboard')}
          className="flex items-center gap-2 text-sm font-bold tracking-widest uppercase transition-colors"
          style={{ color: '#6b7280' }}
          onMouseEnter={e => (e.currentTarget.style.color = '#60a5fa')}
          onMouseLeave={e => (e.currentTarget.style.color = '#6b7280')}
        >
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </button>

        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-widest uppercase" style={{ color: '#d1d5db' }}>
              Telemetry Ingestion
            </h1>
            <p className="text-sm mt-1" style={{ color: '#6b7280' }}>
              {logs.length} logs collected · {filteredLogs.length} matching filter
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleRefresh}
              disabled={loading}
              className="text-sm px-3 py-1 rounded disabled:opacity-40"
              style={{ border: '1px solid #333', color: '#9ca3af' }}
            >
              {loading ? 'Syncing...' : 'Refresh'}
            </button>
            <button
              onClick={() => handleExport('csv')}
              disabled={exporting}
              className="text-sm px-3 py-1 rounded disabled:opacity-40"
              style={{ border: '1px solid #333', color: '#9ca3af' }}
            >
              {exporting ? 'Exporting...' : 'Export CSV'}
            </button>
            <button
              onClick={() => handleExport('json')}
              disabled={exporting}
              className="text-sm px-3 py-1 rounded disabled:opacity-40"
              style={{ border: '1px solid #333', color: '#9ca3af' }}
            >
              Export JSON
            </button>
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2" style={{ color: '#6b7280' }} />
              <input
                type="text"
                placeholder="Search logs..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="text-sm rounded px-2 py-1 pl-9 w-56"
                style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
              />
            </div>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="text-sm rounded px-2 py-1 w-32"
              style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
            >
              <option value="all">All Severity</option>
              {severityOrder.map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="text-sm rounded px-2 py-1 w-32"
              style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
            >
              <option value="all">All Sources</option>
              {sources.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <select
              value={hostFilter}
              onChange={(e) => setHostFilter(e.target.value)}
              className="text-sm rounded px-2 py-1 w-32"
              style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
            >
              <option value="all">All Hosts</option>
              {hosts.map((h) => (
                <option key={h} value={h}>{h}</option>
              ))}
            </select>
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="text-sm rounded px-2 py-1 w-28"
              style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
            >
              <option value="all">All Time</option>
              <option value="1h">Last hour</option>
              <option value="24h">Last 24h</option>
              <option value="7d">Last 7d</option>
            </select>
          </div>
        </div>

        {/* Severity summary bar */}
        <div className="flex gap-2 flex-wrap">
          {severityOrder.map(sev => {
            const s = severityStyle[sev];
            const count = severityCounts[sev] || 0;
            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(severityFilter === sev ? 'all' : sev)}
                className="px-3 py-1.5 rounded text-sm font-bold transition-all"
                style={{
                  background: severityFilter === sev ? s.bg : 'rgba(13,17,23,0.8)',
                  color: s.color,
                  border: `1px solid ${severityFilter === sev ? s.border : 'rgba(75,85,99,0.4)'}`,
                }}
              >
                {sev} <span className="ml-1 font-mono">{count}</span>
              </button>
            );
          })}
        </div>

        {(error || exportError) && (
          <div className="rounded-lg px-4 py-3 text-sm flex items-center justify-between" style={{ background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)', color: '#ff2d55' }}>
            <span>{error || exportError}</span>
            <button onClick={handleRefresh} disabled={loading} className="text-xs font-bold px-3 py-1 rounded ml-4 disabled:opacity-40" style={{ border: '1px solid rgba(255,45,85,0.4)', color: '#ff2d55' }}>
              {loading ? 'Retrying...' : 'Retry'}
            </button>
          </div>
        )}

        {loading && logs.length === 0 && (
          <div className="flex justify-center py-16">
            <div className="w-10 h-10 border-2 border-t-blue-500 border-gray-700 rounded-full animate-spin" />
          </div>
        )}

        {/* Table */}
        <div className="rounded-lg overflow-hidden" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr>
                  <th className="text-sm font-bold uppercase px-4 py-3 text-left" style={{ color: '#6b7280', borderBottom: '1px solid rgba(75,85,99,0.2)' }}>Timestamp</th>
                  <th className="text-sm font-bold uppercase px-4 py-3 text-left" style={{ color: '#6b7280', borderBottom: '1px solid rgba(75,85,99,0.2)' }}>Host</th>
                  <th className="text-sm font-bold uppercase px-4 py-3 text-left" style={{ color: '#6b7280', borderBottom: '1px solid rgba(75,85,99,0.2)' }}>Source</th>
                  <th className="text-sm font-bold uppercase px-4 py-3 text-left" style={{ color: '#6b7280', borderBottom: '1px solid rgba(75,85,99,0.2)' }}>Type</th>
                  <th className="text-sm font-bold uppercase px-4 py-3 text-left" style={{ color: '#6b7280', borderBottom: '1px solid rgba(75,85,99,0.2)' }}>Severity</th>
                  <th className="text-sm font-bold uppercase px-4 py-3 text-left" style={{ color: '#6b7280', borderBottom: '1px solid rgba(75,85,99,0.2)' }}>Message</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-16 text-center text-sm font-bold uppercase" style={{ color: '#6b7280' }}>
                      No logs match the current filters
                    </td>
                  </tr>
                ) : (
                  filteredLogs.map((log, i) => (
                    <LogRow key={log.timestamp + i} log={log} />
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
