import React, { useEffect, useState } from 'react';
import { apiService } from '../services/api';
import { YARAEvent, YARAStats } from '../types';

const YARA: React.FC = () => {
  const [events, setEvents] = useState<YARAEvent[]>([]);
  const [stats, setStats] = useState<YARAStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [hostFilter, setHostFilter] = useState<string>('');
  const [selectedEvent, setSelectedEvent] = useState<YARAEvent | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const params: any = { limit: 200 };
      if (hostFilter) params.host = hostFilter;
      if (severityFilter !== 'all') params.severity = severityFilter;

      const [eventsRes, statsRes] = await Promise.all([
        apiService.getYARAEvents(params),
        apiService.getYARAStats(),
      ]);
      setEvents(eventsRes.data || []);
      setStats(statsRes.data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load YARA data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, [severityFilter, hostFilter]);

  const severityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ background: '#ef4444', color: '#0a0a0a' }}>CRITICAL</span>;
      case 'HIGH': return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ background: '#f59e0b', color: '#0a0a0a' }}>HIGH</span>;
      case 'MEDIUM': return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ background: '#60a5fa', color: '#0a0a0a' }}>MEDIUM</span>;
      case 'LOW': return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ background: '#22c55e', color: '#0a0a0a' }}>LOW</span>;
      default: return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ background: '#6b7280', color: '#0a0a0a' }}>{sev}</span>;
    }
  };

  const hostKeys = stats?.by_host ? Object.keys(stats.by_host) : [];

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold tracking-wider" style={{ color: '#d1d5db' }}>YARA / HOST-BASED IDS</h1>
        <button
          onClick={fetchData}
          className="text-xs px-3 py-1.5 rounded"
          style={{ border: '1px solid #333', color: '#9ca3af' }}
        >
          Refresh
        </button>
      </div>

      {error && (
        <div className="text-red-500 text-sm border border-red-900/50 p-3 bg-red-950/20 rounded">{error}</div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
          <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Total Matches</div>
          <div className="text-3xl font-bold font-mono mt-1" style={{ color: '#d1d5db' }}>{stats?.total_events || 0}</div>
        </div>
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
          <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Critical</div>
          <div className="text-3xl font-bold font-mono mt-1" style={{ color: '#ef4444' }}>{stats?.by_severity?.CRITICAL || 0}</div>
        </div>
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
          <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>High</div>
          <div className="text-3xl font-bold font-mono mt-1" style={{ color: '#f59e0b' }}>{stats?.by_severity?.HIGH || 0}</div>
        </div>
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
          <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Medium</div>
          <div className="text-3xl font-bold font-mono mt-1" style={{ color: '#60a5fa' }}>{stats?.by_severity?.MEDIUM || 0}</div>
        </div>
      </div>

      {/* Hosts summary */}
      {hostKeys.length > 0 && (
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
          <div className="text-xs font-bold uppercase mb-4" style={{ color: '#6b7280' }}>Hosts with YARA Matches</div>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
            {hostKeys.map((host) => (
              <button
                key={host}
                onClick={() => setHostFilter(host === hostFilter ? '' : host)}
                className="p-2 rounded text-xs text-left"
                style={{
                  background: hostFilter === host ? 'rgba(96,165,250,0.1)' : 'rgba(255,255,255,0.03)',
                  border: hostFilter === host ? '1px solid #60a5fa' : '1px solid rgba(75,85,99,0.2)',
                  color: '#9ca3af',
                }}
              >
                <div style={{ color: '#d1d5db' }}>{host}</div>
                <div className="mt-1" style={{ color: '#6b7280' }}>{stats!.by_host[host]} matches</div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Top Rules */}
      {stats?.by_rule_name && Object.keys(stats.by_rule_name).length > 0 && (
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
          <div className="text-xs font-bold uppercase mb-4" style={{ color: '#6b7280' }}>Top Matching Rules</div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
            {Object.entries(stats.by_rule_name)
              .sort(([, a], [, b]) => b - a)
              .slice(0, 12)
              .map(([rule, count]) => (
                <div key={rule} className="p-2 rounded text-xs" style={{ background: 'rgba(255,255,255,0.03)' }}>
                  <div style={{ color: '#d1d5db' }} className="truncate">{rule}</div>
                  <div className="mt-1" style={{ color: '#6b7280' }}>{count} hits</div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Severity Filters */}
      <div className="flex gap-2 flex-wrap">
        {[
          { key: 'all', label: 'All Severities' },
          { key: 'CRITICAL', label: 'CRITICAL' },
          { key: 'HIGH', label: 'HIGH' },
          { key: 'MEDIUM', label: 'MEDIUM' },
          { key: 'LOW', label: 'LOW' },
        ].map((f) => (
          <button
            key={f.key}
            onClick={() => setSeverityFilter(f.key)}
            className="text-xs px-3 py-1.5 rounded"
            style={{
              border: severityFilter === f.key ? '1px solid #60a5fa' : '1px solid #333',
              color: severityFilter === f.key ? '#60a5fa' : '#9ca3af',
              background: severityFilter === f.key ? 'rgba(96,165,250,0.1)' : 'transparent',
            }}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Events Table */}
      <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
        <div className="text-xs font-bold uppercase mb-4" style={{ color: '#6b7280' }}>
          YARA Matches {hostFilter && <span> — Host: {hostFilter}</span>}
        </div>
        {loading && events.length === 0 ? (
          <div className="flex items-center justify-center h-32">
            <div className="w-8 h-8 border-2 border-t-[#333] border-[rgba(75,85,99,0.2)] rounded-full animate-spin" />
          </div>
        ) : events.length === 0 ? (
          <p className="text-sm" style={{ color: '#6b7280' }}>No YARA matches found.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left" style={{ color: '#6b7280', borderBottom: '1px solid rgba(75,85,99,0.2)' }}>
                  <th className="p-2 font-medium">Timestamp</th>
                  <th className="p-2 font-medium">Severity</th>
                  <th className="p-2 font-medium">Host</th>
                  <th className="p-2 font-medium">Rule</th>
                  <th className="p-2 font-medium">File / Process</th>
                  <th className="p-2 font-medium">Tags</th>
                  <th className="p-2 font-medium">Details</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event, idx) => {
                  const meta = event.metadata || {};
                  const tags: string[] = meta.yara_tags || [];
                  return (
                    <React.Fragment key={idx}>
                      <tr
                        className="cursor-pointer"
                        style={{ borderBottom: '1px solid rgba(75,85,99,0.2)' }}
                        onClick={() => setSelectedEvent(selectedEvent === event ? null : event)}
                        onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                        onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                      >
                        <td className="p-2 text-xs" style={{ color: '#6b7280' }}>
                          {new Date(event.timestamp).toLocaleString()}
                        </td>
                        <td className="p-2">{severityBadge(event.severity)}</td>
                        <td className="p-2" style={{ color: '#d1d5db' }}>{event.host}</td>
                        <td className="p-2 font-mono text-xs max-w-[160px] truncate" style={{ color: '#d1d5db' }}>
                          {meta.yara_rule_name || '-'}
                        </td>
                        <td className="p-2 font-mono text-xs max-w-[200px] truncate" style={{ color: '#d1d5db' }}>
                          {meta.yara_file_path || '-'}
                        </td>
                        <td className="p-2">
                          <div className="flex gap-1 flex-wrap">
                            {tags.slice(0, 3).map((tag: string) => (
                              <span key={tag} className="text-xs px-1.5 py-0.5 rounded" style={{ background: 'rgba(255,255,255,0.05)', color: '#6b7280' }}>
                                {tag}
                              </span>
                            ))}
                            {tags.length > 3 && <span className="text-xs" style={{ color: '#6b7280' }}>+{tags.length - 3}</span>}
                          </div>
                        </td>
                        <td className="p-2">
                          <button
                            onClick={(e) => { e.stopPropagation(); setSelectedEvent(selectedEvent === event ? null : event); }}
                            className="text-xs hover:underline"
                            style={{ color: '#60a5fa', background: 'none', border: 'none', cursor: 'pointer' }}
                          >
                            {selectedEvent === event ? 'Hide' : 'Show'}
                          </button>
                        </td>
                      </tr>
                      {selectedEvent === event && (
                        <tr>
                          <td colSpan={7} className="p-4" style={{ background: 'rgba(255,255,255,0.02)' }}>
                            <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                              <div>
                                <span style={{ color: '#6b7280' }}>Rule Name:</span>
                                <div style={{ color: '#f59e0b' }}>{meta.yara_rule_name || '-'}</div>
                              </div>
                              <div>
                                <span style={{ color: '#6b7280' }}>Rule Source:</span>
                                <div style={{ color: '#d1d5db' }}>{meta.yara_rule_source || '-'}</div>
                              </div>
                              <div>
                                <span style={{ color: '#6b7280' }}>File / Process:</span>
                                <div className="break-all" style={{ color: '#d1d5db' }}>{meta.yara_file_path || '-'}</div>
                              </div>
                              <div>
                                <span style={{ color: '#6b7280' }}>Platform:</span>
                                <div style={{ color: '#d1d5db' }}>{meta.platform || '-'}</div>
                              </div>
                              {meta.yara_meta && typeof meta.yara_meta === 'object' && Object.keys(meta.yara_meta).length > 0 && (
                                <div className="col-span-2">
                                  <span style={{ color: '#6b7280' }}>Rule Metadata:</span>
                                  <div className="mt-1 p-2 rounded" style={{ background: 'rgba(255,255,255,0.03)' }}>
                                    {Object.entries(meta.yara_meta).map(([k, v]) => (
                                      <div key={k} className="flex gap-2">
                                        <span style={{ color: '#6b7280' }}>{k}:</span>
                                        <span style={{ color: '#d1d5db' }}>{String(v)}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {meta.yara_strings && Array.isArray(meta.yara_strings) && meta.yara_strings.length > 0 && (
                                <div className="col-span-2">
                                  <span style={{ color: '#6b7280' }}>Matched Strings:</span>
                                  <div className="mt-1 space-y-1">
                                    {meta.yara_strings.map((s: any, si: number) => (
                                      <div key={si} className="p-1.5 rounded text-xs" style={{ background: 'rgba(255,255,255,0.03)' }}>
                                        <span style={{ color: '#f59e0b' }}>{s.identifier || 'unknown'}</span>
                                        <span style={{ color: '#6b7280' }}> @ offset {s.offset}: </span>
                                        <span style={{ color: '#d1d5db' }}>"{s.data}"</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {tags.length > 0 && (
                                <div className="col-span-2">
                                  <span style={{ color: '#6b7280' }}>Tags:</span>
                                  <div className="flex gap-1 mt-1 flex-wrap">
                                    {tags.map((tag: string) => (
                                      <span key={tag} className="text-xs px-2 py-0.5 rounded" style={{ background: 'rgba(255,255,255,0.05)', color: '#d1d5db' }}>
                                        {tag}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default YARA;
