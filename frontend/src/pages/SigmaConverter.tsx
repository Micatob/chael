import React, { useState } from 'react';
import { FileText, Upload, Copy, Check, Plus } from 'lucide-react';
import { apiService } from '../services/api';

const SAMPLE_SIGMA = `title: Suspicious PowerShell Download
id: 8c9b3e7a-1f5d-4a2c-9b8d-3e7a1f5d4a2c
status: experimental
description: Detects PowerShell downloading files from the internet
level: high
detection:
  selection:
    EventID: 4104
    ScriptBlockText:
      - '*Invoke-WebRequest*'
      - '*DownloadFile*'
      - '*Start-BitsTransfer*'
  condition: selection`;

const btnStyle = { border: '1px solid #333', color: '#9ca3af', background: 'transparent', padding: '4px 12px', borderRadius: '4px', fontSize: '12px' };
const cardStyle = { background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '16px' };
const inputStyle = { background: '#1a1a1a', border: '1px solid #333', color: '#d1d5db' };

const SigmaConverter: React.FC = () => {
  const [yamlInput, setYamlInput] = useState('');
  const [converting, setConverting] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [createdRuleId, setCreatedRuleId] = useState<string | null>(null);
  const [csvFile, setCsvFile] = useState<File | null>(null);

  const handleConvertText = async () => {
    if (!yamlInput.trim()) return;
    setError(null);
    setResult(null);
    setCreatedRuleId(null);
    setConverting(true);
    try {
      const res = await apiService.convertSigmaYaml(yamlInput);
      setResult(res.data.rule);
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'Conversion failed');
    } finally {
      setConverting(false);
    }
  };

  const handleConvertFile = async () => {
    if (!csvFile) return;
    setError(null);
    setResult(null);
    setCreatedRuleId(null);
    setConverting(true);
    try {
      const res = await apiService.convertSigmaFile(csvFile);
      setResult(res.data.rule);
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'File conversion failed');
    } finally {
      setConverting(false);
    }
  };

  const handleCreateRule = async () => {
    if (!result) return;
    setError(null);
    try {
      const res = await apiService.createCorrelationRule(result);
      setCreatedRuleId(res.data.rule?.id || result.id);
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'Failed to create rule');
    }
  };

  const loadSample = () => setYamlInput(SAMPLE_SIGMA);

  return (
    <div className="max-w-6xl mx-auto space-y-8">
        <div className="flex items-center gap-3">
          <FileText className="w-6 h-6" style={{ color: '#60a5fa' }} />
          <h1 className="text-xl font-bold tracking-wider" style={{ color: '#60a5fa' }}>SIGMA RULE CONVERTER</h1>
        </div>

        {error && (
          <div className="text-red-500 text-sm border border-red-900/50 p-3 bg-red-950/20 rounded">{error}</div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-6">
            <div style={cardStyle}>
              <div className="flex items-center justify-between mb-4">
                <div className="text-xs font-bold uppercase" style={{ color: '#6b7280' }}>Paste Sigma YAML</div>
                <button onClick={loadSample} style={btnStyle}>Load Sample</button>
              </div>
              <textarea
                value={yamlInput}
                onChange={(e) => setYamlInput(e.target.value)}
                className="w-full h-80 font-mono text-xs leading-relaxed rounded px-2 py-1"
                style={inputStyle}
                spellCheck={false}
                placeholder="Paste Sigma YAML rule here..."
              />
              <div className="flex gap-2 mt-3">
                <button onClick={handleConvertText} disabled={!yamlInput.trim() || converting} className="flex-1 text-xs px-3 py-1.5 rounded" style={btnStyle}>
                  {converting ? 'Converting...' : 'Convert to Rule'}
                </button>
                {yamlInput && (
                  <button onClick={() => { setYamlInput(''); setResult(null); setError(null); }} style={btnStyle}>
                    Clear
                  </button>
                )}
              </div>
            </div>

            <div style={cardStyle}>
              <div className="text-xs font-bold uppercase mb-4" style={{ color: '#6b7280' }}>Or Upload a .yaml / .yml File</div>
              <div className="border border-dashed rounded p-4 text-center" style={{ borderColor: '#333' }}>
                {csvFile ? (
                  <div className="space-y-2">
                    <p className="text-sm" style={{ color: '#d1d5db' }}>{csvFile.name}</p>
                    <div className="flex gap-2 justify-center">
                      <button onClick={handleConvertFile} disabled={converting} style={btnStyle}>
                        {converting ? 'Converting...' : 'Convert File'}
                      </button>
                      <button onClick={() => setCsvFile(null)} style={btnStyle}>Remove</button>
                    </div>
                  </div>
                ) : (
                  <label className="cursor-pointer block">
                    <Upload className="w-8 h-8 mx-auto mb-2" style={{ color: '#6b7280' }} />
                    <span className="text-sm" style={{ color: '#6b7280' }}>Click to select a Sigma YAML file</span>
                    <input type="file" accept=".yaml,.yml" className="hidden" onChange={(e) => setCsvFile(e.target.files?.[0] || null)} />
                  </label>
                )}
              </div>
            </div>
          </div>

          <div>
            <div style={cardStyle}>
              <div className="text-xs font-bold uppercase mb-4" style={{ color: '#6b7280' }}>
                Converted Rule {result && <span style={{ background: 'rgba(34,197,94,0.15)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.3)', borderRadius: '2px', padding: '1px 6px', fontSize: '11px', fontWeight: 700 }}>READY</span>}
              </div>
              {!result ? (
                <div className="flex items-center justify-center h-80" style={{ color: '#6b7280' }}>
                  <div className="text-center">
                    <FileText className="w-12 h-12 mx-auto mb-3 opacity-30" />
                    <p className="text-sm">Paste Sigma YAML or upload a file to convert</p>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="p-3 rounded font-mono text-xs" style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(75,85,99,0.2)' }}>
                    {Object.entries(result).map(([key, value]) => (
                      key !== 'condition' ? (
                        <div key={key} className="flex py-1" style={{ borderBottom: '1px solid rgba(75,85,99,0.3)' }}>
                          <span className="w-32 flex-shrink-0" style={{ color: '#6b7280' }}>{key}</span>
                          <span style={{ color: '#d1d5db' }}>{String(value)}</span>
                        </div>
                      ) : null
                    ))}
                    {result.condition && (
                      <div className="flex py-1" style={{ borderBottom: '1px solid rgba(75,85,99,0.3)' }}>
                        <span className="w-32 flex-shrink-0" style={{ color: '#6b7280' }}>condition.field</span>
                        <span style={{ color: '#d1d5db' }}>{result.condition.field}</span>
                      </div>
                    )}
                    {result.condition && (
                      <div className="flex py-1" style={{ borderBottom: '1px solid rgba(75,85,99,0.3)' }}>
                        <span className="w-32 flex-shrink-0" style={{ color: '#6b7280' }}>condition.operator</span>
                        <span style={{ color: '#d1d5db' }}>{result.condition.operator}</span>
                      </div>
                    )}
                    {result.condition && (
                      <div className="flex py-1">
                        <span className="w-32 flex-shrink-0" style={{ color: '#6b7280' }}>condition.value</span>
                        <span style={{ color: '#22c55e' }}>{result.condition.value}</span>
                      </div>
                    )}
                  </div>

                  <div className="flex gap-2">
                    <button onClick={handleCreateRule} disabled={!!createdRuleId} className="flex-1 text-xs px-3 py-1.5 rounded" style={btnStyle}>
                      {createdRuleId ? (
                        <><Check className="w-4 h-4 mr-1" /> Created</>
                      ) : (
                        <><Plus className="w-4 h-4 mr-1" /> Create Correlation Rule</>
                      )}
                    </button>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(JSON.stringify(result, null, 2));
                      }}
                      style={btnStyle}
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  </div>

                  {createdRuleId && (
                    <div className="text-sm p-2 rounded text-center" style={{ background: 'rgba(34,197,94,0.1)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.3)' }}>
                      Rule created: <span className="font-mono">{createdRuleId}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
  );
};

export default SigmaConverter;
