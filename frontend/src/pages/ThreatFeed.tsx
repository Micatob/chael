import React, { useState } from 'react';
import { Search, Upload, FileUp, Globe, Hash, Bug } from 'lucide-react';
import { apiService } from '../services/api';
import type { IOCItem } from '../types';

const typeIcon: Record<string, React.ReactNode> = {
  IP_ADDRESS: <Globe className="w-4 h-4" />,
  DOMAIN: <Globe className="w-4 h-4" />,
  URL: <Globe className="w-4 h-4" />,
  HASH_MD5: <Hash className="w-4 h-4" />,
  HASH_SHA1: <Hash className="w-4 h-4" />,
  HASH_SHA256: <Hash className="w-4 h-4" />,
};

const badgeStyle = (variant: string) => {
  switch (variant) {
    case 'severity-critical': return { background: 'rgba(239,68,68,0.15)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '2px', padding: '1px 6px', fontSize: '11px', fontWeight: 700 };
    case 'severity-high': return { background: 'rgba(245,158,11,0.15)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.3)', borderRadius: '2px', padding: '1px 6px', fontSize: '11px', fontWeight: 700 };
    default: return { background: 'rgba(96,165,250,0.15)', color: '#60a5fa', border: '1px solid rgba(96,165,250,0.3)', borderRadius: '2px', padding: '1px 6px', fontSize: '11px', fontWeight: 700 };
  }
};

const btnStyle = { border: '1px solid #333', color: '#9ca3af', background: 'transparent', padding: '4px 12px', borderRadius: '4px', fontSize: '12px' };
const cardStyle = { background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' };
const inputStyle = { background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' };

const ThreatFeed: React.FC = () => {
  const [bulkInput, setBulkInput] = useState('');
  const [csvFile, setCsvFile] = useState<File | null>(null);
  const [uploadResult, setUploadResult] = useState<{ uploaded: number; errors: any[] } | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [enrichType, setEnrichType] = useState<'ip' | 'domain' | 'hash'>('ip');
  const [enrichValue, setEnrichValue] = useState('');
  const [enrichResult, setEnrichResult] = useState<{ key: string; matches: IOCItem[]; total: number } | null>(null);
  const [enriching, setEnriching] = useState(false);

  const handleBulkUpload = async () => {
    setError(null);
    setUploadResult(null);
    let iocs: any[];
    try {
      iocs = JSON.parse(bulkInput);
      if (!Array.isArray(iocs)) throw new Error('Input must be a JSON array');
    } catch (e: any) {
      setError('Invalid JSON: ' + e.message);
      return;
    }
    setUploading(true);
    try {
      const res = await apiService.bulkUploadIOCs(iocs);
      setUploadResult(res.data);
      setBulkInput('');
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  const handleCSVUpload = async () => {
    if (!csvFile) return;
    setError(null);
    setUploadResult(null);
    setUploading(true);
    try {
      const res = await apiService.uploadIOCSFromCSV(csvFile);
      setUploadResult(res.data);
      setCsvFile(null);
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'CSV upload failed');
    } finally {
      setUploading(false);
    }
  };

  const handleEnrich = async () => {
    if (!enrichValue.trim()) return;
    setError(null);
    setEnrichResult(null);
    setEnriching(true);
    try {
      let res;
      if (enrichType === 'ip') res = await apiService.enrichIP(enrichValue.trim());
      else if (enrichType === 'domain') res = await apiService.enrichDomain(enrichValue.trim());
      else res = await apiService.enrichHash(enrichValue.trim());
      const data = res.data;
      const key = enrichType === 'ip' ? 'ip' : enrichType === 'domain' ? 'domain' : 'hash';
      setEnrichResult({ key: data[key] || enrichValue, matches: data.matches || [], total: data.total || 0 });
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'Enrichment failed');
    } finally {
      setEnriching(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8">
        <div className="flex items-center gap-3">
          <Bug className="w-6 h-6" style={{ color: '#60a5fa' }} />
          <h1 className="text-xl font-bold tracking-wider" style={{ color: '#60a5fa' }}>THREAT INTELLIGENCE</h1>
        </div>

        {error && (
          <div className="text-red-500 text-sm border border-red-900/50 p-3 bg-red-950/20 rounded">{error}</div>
        )}

        {uploadResult && (
          <div style={{ ...cardStyle, border: '1px solid rgba(96,165,250,0.4)' }}>
            <div className="flex items-center justify-between">
              <div>
                <span style={{ color: '#60a5fa', fontWeight: 700 }}>Upload Complete</span>
                <span className="ml-3 text-sm" style={{ color: '#6b7280' }}>{uploadResult.uploaded} IOCs uploaded</span>
                {uploadResult.errors.length > 0 && (
                  <span className="ml-3 text-sm text-red-500">{uploadResult.errors.length} errors</span>
                )}
              </div>
              <button onClick={() => setUploadResult(null)} style={btnStyle}>Dismiss</button>
            </div>
          </div>
        )}

        <div style={cardStyle}>
          <div className="flex items-center gap-2 mb-4">
            <Upload className="w-5 h-5" style={{ color: '#60a5fa' }} />
            <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Upload IOCs</div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-xs font-bold tracking-widest mb-2" style={{ color: '#6b7280' }}>JSON Bulk</label>
              <textarea
                value={bulkInput}
                onChange={(e) => setBulkInput(e.target.value)}
                placeholder='[{"type": "IP_ADDRESS", "value": "1.2.3.4", "confidence": "high", "tags": ["malware"]}]'
                className="w-full h-32 font-mono text-xs rounded px-2 py-1"
                style={inputStyle}
                spellCheck={false}
              />
              <button onClick={handleBulkUpload} disabled={!bulkInput.trim() || uploading} className="mt-2 w-full text-xs px-3 py-1.5 rounded" style={{ ...btnStyle }}>
                {uploading ? 'Uploading...' : 'Upload JSON'}
              </button>
            </div>

            <div>
              <label className="block text-xs font-bold tracking-widest mb-2" style={{ color: '#6b7280' }}>CSV File</label>
              <div className="border border-dashed rounded p-4 text-center" style={{ borderColor: '#333' }}>
                {csvFile ? (
                  <div className="space-y-2">
                    <p className="text-sm" style={{ color: '#d1d5db' }}>{csvFile.name} ({(csvFile.size / 1024).toFixed(1)} KB)</p>
                    <div className="flex gap-2 justify-center">
                      <button onClick={handleCSVUpload} disabled={uploading} className="text-xs px-3 py-1.5 rounded" style={btnStyle}>{uploading ? 'Uploading...' : 'Upload CSV'}</button>
                      <button onClick={() => setCsvFile(null)} className="text-xs px-3 py-1.5 rounded" style={btnStyle}>Remove</button>
                    </div>
                  </div>
                ) : (
                  <label className="cursor-pointer block">
                    <FileUp className="w-8 h-8 mx-auto mb-2" style={{ color: '#6b7280' }} />
                    <span className="text-sm" style={{ color: '#6b7280' }}>Click to select CSV</span>
                    <input type="file" accept=".csv" className="hidden" onChange={(e) => setCsvFile(e.target.files?.[0] || null)} />
                  </label>
                )}
              </div>
              <div className="mt-2 text-xs" style={{ color: '#6b7280' }}>
                CSV columns: type, value, description, confidence, tags
              </div>
            </div>
          </div>
        </div>

        <div style={cardStyle}>
          <div className="flex items-center gap-2 mb-4">
            <Search className="w-5 h-5" style={{ color: '#60a5fa' }} />
            <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Enrichment Lookup</div>
          </div>

          <div className="flex flex-wrap gap-2 mb-4">
            {(['ip', 'domain', 'hash'] as const).map((t) => (
              <button
                key={t}
                onClick={() => { setEnrichType(t); setEnrichResult(null); }}
                className="px-3 py-1.5 rounded text-xs font-bold tracking-widest uppercase"
                style={enrichType === t
                  ? { background: 'rgba(96,165,250,0.2)', color: '#60a5fa', border: '1px solid rgba(96,165,250,0.5)' }
                  : { color: '#6b7280', border: '1px solid rgba(75,85,99,0.2)', background: 'transparent' }
                }
              >
                {t === 'ip' ? 'IP Address' : t === 'domain' ? 'Domain' : 'File Hash'}
              </button>
            ))}
          </div>

          <div className="flex gap-2">
            <input
              type="text"
              value={enrichValue}
              onChange={(e) => setEnrichValue(e.target.value)}
              placeholder={enrichType === 'ip' ? '8.8.8.8' : enrichType === 'domain' ? 'example.com' : 'sha256 hash...'}
              className="flex-1 font-mono text-sm rounded px-2 py-1"
              style={inputStyle}
              onKeyDown={(e) => e.key === 'Enter' && handleEnrich()}
            />
            <button onClick={handleEnrich} disabled={!enrichValue.trim() || enriching} className="text-xs px-3 py-1.5 rounded" style={btnStyle}>
              {enriching ? 'Searching...' : 'Lookup'}
            </button>
          </div>

          {enrichResult && (
            <div className="mt-4 space-y-2 max-h-80 overflow-y-auto">
              <div className="text-sm mb-2" style={{ color: '#6b7280' }}>
                {enrichResult.total} match{enrichResult.total !== 1 ? 'es' : ''} for <span className="font-mono" style={{ color: '#60a5fa' }}>{enrichResult.key}</span>
              </div>
              {enrichResult.matches.length === 0 ? (
                <p className="text-sm" style={{ color: '#6b7280' }}>No matches found.</p>
              ) : (
                enrichResult.matches.map((m, i) => (
                  <div key={m.ioc_id || i} style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '12px' }}>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs" style={{ color: '#60a5fa' }}>{typeIcon[m.type]}</span>
                      <span className="font-mono text-sm" style={{ color: '#d1d5db' }}>{m.value}</span>
                      <span style={badgeStyle(m.confidence === 'high' ? 'severity-critical' : m.confidence === 'medium' ? 'severity-high' : 'info')}>
                        {m.confidence}
                      </span>
                      <span style={badgeStyle('info')}>{m.type}</span>
                    </div>
                    {m.description && <div className="text-xs mt-1" style={{ color: '#6b7280' }}>{m.description}</div>}
                    {m.tags && m.tags.length > 0 && (
                      <div className="flex gap-1 mt-1">
                        {m.tags.map((t, ti) => (
                          <span key={ti} className="text-xs" style={{ background: 'rgba(107,114,128,0.2)', color: '#6b7280', borderRadius: '2px', padding: '2px 6px' }}>{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>
  );
};

export default ThreatFeed;
