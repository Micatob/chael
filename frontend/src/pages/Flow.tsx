import React, { useEffect, useState, useCallback } from 'react';
import { apiService } from '../services/api';
import { FlowRecord, FlowStats } from '../types';

const protocolBadge = (proto: string) => {
  switch (proto) {
    case 'TCP': return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ background: '#ef4444', color: '#0a0a0a' }}>TCP</span>;
    case 'UDP': return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ background: '#f59e0b', color: '#0a0a0a' }}>UDP</span>;
    case 'ICMP': return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ background: '#22c55e', color: '#0a0a0a' }}>ICMP</span>;
    default: return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ background: '#60a5fa', color: '#0a0a0a' }}>{proto}</span>;
  }
};

const directionLabel = (dir: string) => {
  switch (dir) {
    case 'ingress': return <span style={{ color: '#f59e0b' }}>IN</span>;
    case 'egress': return <span style={{ color: '#22c55e' }}>OUT</span>;
    default: return <span style={{ color: '#6b7280' }}>---</span>;
  }
};

const formatBytes = (bytes: number) => {
  if (bytes >= 1024 * 1024 * 1024) return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
  if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return bytes + ' B';
};

const Flow: React.FC = () => {
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [stats, setStats] = useState<FlowStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [protocolFilter, setProtocolFilter] = useState<string>('all');
  const [minBytes, setMinBytes] = useState<string>('');
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: any = { limit: 200 };
      if (protocolFilter !== 'all') params.protocol = protocolFilter;
      if (minBytes) params.min_bytes = parseInt(minBytes, 10);

      const [flowsRes, statsRes] = await Promise.all([
        apiService.getFlows(params),
        apiService.getFlowStats(),
      ]);
      setFlows(flowsRes.data || []);
      setStats(statsRes.data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load flow data');
    } finally {
      setLoading(false);
    }
  }, [protocolFilter, minBytes]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, [fetchData]);

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold tracking-wider" style={{ color: '#d1d5db' }}>NETWORK FLOWS</h1>
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
          <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Flows (24h)</div>
          <div className="text-3xl font-bold font-mono mt-1" style={{ color: '#d1d5db' }}>{stats?.total_flows_24h || 0}</div>
        </div>
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
          <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Traffic Volume</div>
          <div className="text-3xl font-bold font-mono mt-1" style={{ color: '#22c55e' }}>{stats?.total_megabytes || 0} MB</div>
        </div>
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
          <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Unique Source IPs</div>
          <div className="text-3xl font-bold font-mono mt-1" style={{ color: '#f59e0b' }}>{stats?.unique_src_ips || 0}</div>
        </div>
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
          <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Unique Dest IPs</div>
          <div className="text-3xl font-bold font-mono mt-1" style={{ color: '#ef4444' }}>{stats?.unique_dst_ips || 0}</div>
        </div>
      </div>

      {/* Top Talkers */}
      {stats?.top_src_ips && stats.top_src_ips.length > 0 && (
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
          <div className="text-xs font-bold uppercase mb-4" style={{ color: '#6b7280' }}>Top Talkers (Source IPs)</div>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-2">
            {stats.top_src_ips.map((item: any) => (
              <div key={item.ip} className="p-2 rounded text-xs" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
                <div style={{ color: '#d1d5db' }}>{item.ip}</div>
                <div className="mt-1" style={{ color: '#6b7280' }}>{item.count} flows</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Top Ports */}
      {stats?.top_ports && stats.top_ports.length > 0 && (
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
          <div className="text-xs font-bold uppercase mb-4" style={{ color: '#6b7280' }}>Top Destination Ports</div>
          <div className="flex gap-2 flex-wrap">
            {stats.top_ports.map((item: any) => (
              <span key={item.port} className="px-3 py-1 rounded text-xs font-mono" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', color: '#d1d5db' }}>
                {item.port} <span style={{ color: '#6b7280' }}>({item.count})</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-2 flex-wrap items-center">
        {[
          { key: 'all', label: 'All Protocols' },
          { key: 'TCP', label: 'TCP' },
          { key: 'UDP', label: 'UDP' },
          { key: 'ICMP', label: 'ICMP' },
        ].map((f) => (
          <button
            key={f.key}
            onClick={() => setProtocolFilter(f.key)}
            className="text-xs px-3 py-1.5 rounded"
            style={{
              border: protocolFilter === f.key ? '1px solid #60a5fa' : '1px solid #333',
              color: protocolFilter === f.key ? '#60a5fa' : '#9ca3af',
              background: protocolFilter === f.key ? 'rgba(96,165,250,0.1)' : 'transparent',
            }}
          >
            {f.label}
          </button>
        ))}
        <input
          type="number"
          placeholder="Min bytes"
          value={minBytes}
          onChange={(e) => setMinBytes(e.target.value)}
          className="text-xs rounded px-2 py-1 ml-2 w-24"
          style={{ background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' }}
        />
      </div>

      {/* Flows Table */}
      <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' }}>
        <div className="text-xs font-bold uppercase mb-4" style={{ color: '#6b7280' }}>
          Flow Records {protocolFilter !== 'all' && <span style={{ color: '#6b7280' }}>— Protocol: {protocolFilter}</span>}
        </div>
        {loading && flows.length === 0 ? (
          <div className="flex items-center justify-center h-32">
            <div className="w-8 h-8 border-2 border-t-[#333] border-[rgba(75,85,99,0.2)] rounded-full animate-spin" />
          </div>
        ) : flows.length === 0 ? (
          <p className="text-sm" style={{ color: '#6b7280' }}>No flow records found. Ensure NetFlow sources are sending data to port 2055.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left" style={{ color: '#6b7280', borderBottom: '1px solid rgba(75,85,99,0.2)' }}>
                  <th className="p-2 font-medium">Timestamp</th>
                  <th className="p-2 font-medium">Dir</th>
                  <th className="p-2 font-medium">Source</th>
                  <th className="p-2 font-medium">Destination</th>
                  <th className="p-2 font-medium">Proto</th>
                  <th className="p-2 font-medium">Bytes</th>
                  <th className="p-2 font-medium">Pkts</th>
                  <th className="p-2 font-medium">Duration</th>
                </tr>
              </thead>
              <tbody>
                {flows.map((flow, idx) => (
                  <React.Fragment key={idx}>
                    <tr
                      className="cursor-pointer"
                      style={{ borderBottom: '1px solid rgba(75,85,99,0.2)' }}
                      onClick={() => setSelectedFlow(selectedFlow === flow ? null : flow)}
                      onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                      onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                    >
                      <td className="p-2 text-xs" style={{ color: '#6b7280' }}>
                        {new Date(flow.timestamp).toLocaleString()}
                      </td>
                      <td className="p-2">{directionLabel(flow.direction)}</td>
                      <td className="p-2 font-mono text-xs" style={{ color: '#d1d5db' }}>
                        {flow.src_ip}:{flow.src_port}
                      </td>
                      <td className="p-2 font-mono text-xs" style={{ color: '#d1d5db' }}>
                        {flow.dst_ip}:{flow.dst_port}
                      </td>
                      <td className="p-2">{protocolBadge(flow.protocol)}</td>
                      <td className="p-2 font-mono text-xs" style={{ color: '#6b7280' }}>{formatBytes(flow.bytes)}</td>
                      <td className="p-2" style={{ color: '#6b7280' }}>{flow.packets}</td>
                      <td className="p-2" style={{ color: '#6b7280' }}>{flow.duration_seconds.toFixed(1)}s</td>
                    </tr>
                    {selectedFlow === flow && (
                      <tr>
                        <td colSpan={8} className="p-4" style={{ background: 'rgba(255,255,255,0.02)' }}>
                          <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                            <div>
                              <span style={{ color: '#6b7280' }}>Source IP:</span>
                              <div style={{ color: '#d1d5db' }}>{flow.src_ip}</div>
                            </div>
                            <div>
                              <span style={{ color: '#6b7280' }}>Dest IP:</span>
                              <div style={{ color: '#d1d5db' }}>{flow.dst_ip}</div>
                            </div>
                            <div>
                              <span style={{ color: '#6b7280' }}>Source Port:</span>
                              <div style={{ color: '#d1d5db' }}>{flow.src_port}</div>
                            </div>
                            <div>
                              <span style={{ color: '#6b7280' }}>Dest Port:</span>
                              <div style={{ color: '#d1d5db' }}>{flow.dst_port}</div>
                            </div>
                            <div>
                              <span style={{ color: '#6b7280' }}>Protocol:</span>
                              <div style={{ color: '#d1d5db' }}>{flow.protocol}</div>
                            </div>
                            <div>
                              <span style={{ color: '#6b7280' }}>Direction:</span>
                              <div style={{ color: '#d1d5db' }}>{flow.direction}</div>
                            </div>
                            {flow.src_host && (
                              <div>
                                <span style={{ color: '#6b7280' }}>Source Host:</span>
                                <div style={{ color: '#d1d5db' }}>{flow.src_host}</div>
                              </div>
                            )}
                            {flow.dst_host && (
                              <div>
                                <span style={{ color: '#6b7280' }}>Dest Host:</span>
                                <div style={{ color: '#d1d5db' }}>{flow.dst_host}</div>
                              </div>
                            )}
                            <div>
                              <span style={{ color: '#6b7280' }}>Bytes:</span>
                              <div style={{ color: '#d1d5db' }}>{formatBytes(flow.bytes)}</div>
                            </div>
                            <div>
                              <span style={{ color: '#6b7280' }}>Packets:</span>
                              <div style={{ color: '#d1d5db' }}>{flow.packets}</div>
                            </div>
                            <div>
                              <span style={{ color: '#6b7280' }}>Duration:</span>
                              <div style={{ color: '#d1d5db' }}>{flow.duration_seconds.toFixed(2)}s</div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default Flow;
