import axios, { AxiosInstance, AxiosResponse } from 'axios';
import { NormalizedLog, Incident, LoginCredentials, User, LogStats, AnalyticsOverview, InvestigationResult, EnrichResult, PendingAction, NotificationChannelConfig, FlowRecord, FlowStats, YARAEvent, YARAStats } from '../types';

class ApiService {
  private client: AxiosInstance;
  private baseURL: string;

  constructor() {
    this.baseURL = '';
    this.client = axios.create({
      baseURL: this.baseURL,
      headers: {
        'Content-Type': 'application/json',
      },
      withCredentials: true,
      timeout: 15000,
    });

    // Request interceptor for auth tokens
    this.client.interceptors.request.use((config: any) => {
      const token = localStorage.getItem('s2_token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response: any) => response,
      (error: any) => {
        const status = error.response?.status;
        const url: string = error.config?.url || '';
        // Don't redirect on login itself or on background polling that will be retried
        const isLogin = url.includes('/api/auth/login');
        const isBackgroundPoll = url.includes('/api/logs/') || url.includes('/api/analytics/') || url.includes('/api/soar/history') || url.includes('/api/correlation/rules');
        if (status === 401 && !isLogin) {
          // Only redirect if user was previously authenticated (token existed) — prevents loop on first load
          const hadToken = !!localStorage.getItem('s2_token');
          if (hadToken) {
            localStorage.removeItem('s2_token');
            window.dispatchEvent(new Event('authchange'));
            // Avoid hard redirect loop during Dashboard Promise.allSettled polling
            if (!isBackgroundPoll) {
              window.location.href = '/login';
            }
          }
        }
        return Promise.reject(error);
      }
    );
  }

  // Auth
  async login(credentials: LoginCredentials): Promise<AxiosResponse<{ user: User }>> {
    return this.client.post('/api/auth/login', credentials);
  }

  async logout(): Promise<AxiosResponse> {
    return this.client.post('/api/auth/logout');
  }

  // Logs
  async ingestLog(log: NormalizedLog): Promise<AxiosResponse<{ status: string }>> {
    return this.client.post('/api/logs/ingest', log);
  }

  async ingestRawLog(sourceType: string, payload: any): Promise<AxiosResponse<{ status: string }>> {
    return this.client.post(`/api/logs/raw/${sourceType}`, payload);
  }

  async getLogs(limit = 100, offset = 0, search?: string, severity?: string): Promise<AxiosResponse<NormalizedLog[]>> {
    const params: any = { limit, offset, fields: 'timestamp,host,source,severity,message' };
    if (search) params.search = search;
    if (severity) params.severity = severity;
    return this.client.get('/api/logs/', { params });
  }

  async getLogStats(): Promise<AxiosResponse<LogStats>> {
    return this.client.get('/api/logs/stats');
  }

  async verifyLogsIntegrity(limit = 200): Promise<AxiosResponse<{ ok: boolean; checked: number; mismatched: number; samples: any[] }>> {
    return this.client.get('/api/logs/verify', { params: { limit } });
  }

  async exportLogs(format: 'json' | 'csv' = 'json'): Promise<AxiosResponse<{ data: any[] }>> {
    return this.client.get('/api/logs/export', { params: { format } });
  }

  // Incidents
  async getIncidents(): Promise<AxiosResponse<Incident[]>> {
    return this.client.get('/api/incidents/');
  }

  async createIncident(incident: Omit<Incident, 'incident_id'>): Promise<AxiosResponse<Incident>> {
    return this.client.post('/api/incidents/create', incident);
  }

  async getIncident(id: string): Promise<AxiosResponse<Incident>> {
    return this.client.get(`/api/incidents/${id}`);
  }

  async investigateIncident(id: string): Promise<AxiosResponse<InvestigationResult>> {
    return this.client.post(`/api/incidents/${id}/investigate`, undefined, { timeout: 60000 });
  }

  async externalThreatHunt(id: string): Promise<AxiosResponse<{
    incident_id: string;
    found: boolean;
    hunt_timestamp: string;
    iocs_extracted: {
      ip_addresses: string[];
      cve_ids: string[];
      hashes: string[];
      domains: string[];
    };
    external_intel: Record<string, any>;
  }>> {
    return this.client.post(`/api/incidents/${id}/external-hunt`, undefined, { timeout: 60000 });
  }

  async updateIncidentStatus(id: string, status: Incident['status']): Promise<AxiosResponse> {
    return this.client.post(`/api/incidents/${id}/update`, { status });
  }

  async mitigateIncident(id: string, action: { action_type: string; target: string; reason: string }): Promise<AxiosResponse> {
    return this.client.post(`/api/incidents/${id}/mitigate`, action);
  }

  async getLogsAdvanced(params: {
    limit?: number;
    offset?: number;
    search?: string;
    severity?: string;
    host?: string;
    source?: string;
    sort_by?: string;
    sort_order?: string;
  }): Promise<AxiosResponse<NormalizedLog[]>> {
    return this.client.get('/api/logs/', { params });
  }

  async advancedHunt(query: any, limit?: number): Promise<AxiosResponse<{ hits: any[]; total: number; took: number; query: any }>> {
    return this.client.post('/api/logs/hunt', query, { params: { limit } });
  }

  async huntIncidents(params: {
    search?: string;
    status?: string;
    risk_score_min?: number;
    risk_score_max?: number;
    host?: string;
    attack_type?: string;
    limit?: number;
    offset?: number;
    sort_by?: string;
    sort_order?: string;
  }): Promise<AxiosResponse<{ hits: any[]; total: number; took: number }>> {
    return this.client.post('/api/incidents/hunt', params);
  }

  // Correlation
  async processLogForCorrelation(log: NormalizedLog): Promise<AxiosResponse<{ status: string }>> {
    return this.client.post('/api/correlation/process', log);
  }

  // SOAR
  async triggerSOAR(incident: Incident): Promise<AxiosResponse<{ status: string }>> {
    return this.client.post('/api/soar/trigger', incident);
  }

  // Analytics - removed (lightweight dashboard stats)
  async getAnalyticsOverview(): Promise<AxiosResponse<AnalyticsOverview>> {
    return this.client.get('/api/analytics/overview');
  }

  async getSOARHistory(limit = 200): Promise<AxiosResponse<{ history: any[] }>> {
    return this.client.get('/api/soar/history', { params: { limit } });
  }

  // Agent Management & Enrollment
  async listAgents(): Promise<AxiosResponse<Array<{ agent_id: string; hostname: string; last_seen: string; current_version: string; online: boolean }>>> {
    return this.client.get('/api/auth/agents');
  }

  async registerAgent(hostname: string, metadata?: Record<string, any>): Promise<AxiosResponse<{ agent_id: string; agent_key: string; hostname: string }>> {
    return this.client.post('/api/auth/agent/register', { hostname, metadata: metadata || {} });
  }

  async revokeAgent(agentId: string): Promise<AxiosResponse> {
    return this.client.delete(`/api/auth/agent/${agentId}`);
  }

  async deleteAgent(agentId: string): Promise<AxiosResponse> {
    return this.client.delete(`/api/auth/agent/${agentId}/hard`);
  }

  async rotateAgentKey(agentId: string): Promise<AxiosResponse<{ agent_id: string; agent_key: string }>> {
    return this.client.post(`/api/auth/agent/${agentId}/rotate`);
  }

  async markAgentOnline(agentId: string): Promise<AxiosResponse<{ status: string; agent_id: string }>> {
    return this.client.post(`/api/auth/agent/${agentId}/mark-online`);
  }

  async purgeAllAgents(): Promise<AxiosResponse<{ message: string; count: number }>> {
    return this.client.delete('/api/auth/agents/purge');
  }

  async listEnrollmentKeys(): Promise<AxiosResponse<Array<{ key: string; created_at: string; used: boolean; used_at: string | null; used_by_hostname: string | null; revoked: boolean }>>> {
    return this.client.get('/api/auth/enrollment/keys');
  }

  async generateEnrollmentKey(): Promise<AxiosResponse<{ key: string; created_at: string }>> {
    return this.client.post('/api/auth/enrollment/generate');
  }

  async revokeEnrollmentKey(key: string): Promise<AxiosResponse> {
    return this.client.delete(`/api/auth/enrollment/${key}`);
  }

  // Correlation Rules
  async listCorrelationRules(): Promise<AxiosResponse<Array<{ id: string; name: string; description: string; enabled: boolean; threshold: number; risk_score: number }>>> {
    return this.client.get('/api/correlation/rules/');
  }

  async toggleCorrelationRule(ruleId: string): Promise<AxiosResponse<{ status: string; rule_id: string; enabled: boolean }>> {
    return this.client.patch(`/api/correlation/rules/${ruleId}/toggle`);
  }

  async createCorrelationRule(rule: { id: string; name: string; condition: { field: string; operator: string; value: string }; threshold?: number; window_seconds?: number; risk_score?: number; description?: string }): Promise<AxiosResponse> {
    return this.client.post('/api/correlation/rules/', rule);
  }

  async deleteCorrelationRule(ruleId: string): Promise<AxiosResponse> {
    return this.client.delete(`/api/correlation/rules/${ruleId}`);
  }

  // Sigma Rule Conversion
  async convertSigmaYaml(yaml: string): Promise<AxiosResponse<{ status: string; rule: any }>> {
    return this.client.post('/api/correlation/sigma/convert/text', { yaml });
  }

  async convertSigmaFile(file: File): Promise<AxiosResponse<{ status: string; rule: any }>> {
    const formData = new FormData();
    formData.append('file', file);
    return this.client.post('/api/correlation/sigma/convert', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  }

  // Threat Feed (IOC)
  async bulkUploadIOCs(iocs: Array<{ type: string; value: string; description?: string; confidence?: string; tags?: string[] }>): Promise<AxiosResponse<{ status: string; uploaded: number; errors: any[] }>> {
    return this.client.post('/api/threat-feed/iocs/bulk', { iocs });
  }

  async uploadIOCSFromCSV(file: File): Promise<AxiosResponse<{ status: string; uploaded: number; errors: any[] }>> {
    const formData = new FormData();
    formData.append('file', file);
    return this.client.post('/api/threat-feed/iocs/bulk/csv', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  }

  async enrichIP(ip: string): Promise<AxiosResponse<EnrichResult>> {
    return this.client.get(`/api/threat-feed/enrich/ip/${encodeURIComponent(ip)}`);
  }
  async enrichDomain(domain: string): Promise<AxiosResponse<EnrichResult>> {
    return this.client.get(`/api/threat-feed/enrich/domain/${encodeURIComponent(domain)}`);
  }

  async enrichHash(hash: string): Promise<AxiosResponse<EnrichResult>> {
    return this.client.get(`/api/threat-feed/enrich/hash/${encodeURIComponent(hash)}`);
  }

  // Live external intel (incident service — free ip-api/NVD + keyed VT/AbuseIPDB/Shodan/OTX/GreyNoise)
  async enrichStatus(): Promise<AxiosResponse<any>> {
    return this.client.get('/api/incidents/enrich/status');
  }

  async enrichIoc(itype: string, value: string): Promise<AxiosResponse<any>> {
    return this.client.get('/api/incidents/enrich/ioc', { params: { itype, value }, timeout: 30000 });
  }

  // SOAR
  async getSOARPendingActions(incidentId: string): Promise<AxiosResponse<{ incident_id: string; pending_actions: PendingAction[] }>> {
    return this.client.get(`/api/soar/pending/${incidentId}`);
  }

  async approveSOARAction(incidentId: string, actionId: string): Promise<AxiosResponse<{ status: string; incident_id: string; action_id: string }>> {
    return this.client.post(`/api/soar/approve/${incidentId}/${actionId}`);
  }

  async rejectSOARAction(incidentId: string, actionId: string): Promise<AxiosResponse<{ status: string; incident_id: string; action_id: string }>> {
    return this.client.post(`/api/soar/reject/${incidentId}/${actionId}`);
  }

  async getAllSOARPending(): Promise<AxiosResponse<{ pending_actions: Array<PendingAction & { incident_id: string; created_at?: string }> }>> {
    return this.client.get('/api/soar/pending');
  }

  // ── Contain recovery (local backends) ──
  async unisolateHost(host: string, incidentId?: string): Promise<AxiosResponse<any>> {
    return this.client.post('/api/soar/unisolate', { host, incident_id: incidentId });
  }

  async unblockIp(ip: string, incidentId?: string): Promise<AxiosResponse<any>> {
    return this.client.post('/api/soar/unblock', { ip, incident_id: incidentId });
  }

  // ── Agent response tasks (remote contain / recover) ──
  async queueAgentTask(task: { action: string; target: string; incident_id?: string; agent_id?: string; hostname?: string; duration_minutes?: number }): Promise<AxiosResponse<{ status: string; task: any }>> {
    return this.client.post('/api/soar/agent/tasks', task);
  }

  async listAgentTasks(): Promise<AxiosResponse<{ tasks: any[] }>> {
    return this.client.get('/api/soar/agent/tasks/all');
  }

  async dryRunPlaybook(incident: any, playbook?: string, actions?: any[]): Promise<AxiosResponse<any>> {
    return this.client.post('/api/soar/playbooks/dry-run', { incident, playbook, actions });
  }

  async getPlaybookVersions(name: string): Promise<AxiosResponse<{ name: string; versions: any[] }>> {
    return this.client.get(`/api/soar/playbooks/${encodeURIComponent(name)}/versions`);
  }

  async rollbackPlaybook(name: string, version: number): Promise<AxiosResponse<any>> {
    return this.client.post(`/api/soar/playbooks/${encodeURIComponent(name)}/rollback/${version}`);
  }

  async getAgentHeartbeats(agentId: string, limit = 50): Promise<AxiosResponse<Array<{ timestamp: string; status?: string }>>> {
    return this.client.get(`/api/agents/${agentId}/heartbeats`, { params: { limit } });
  }

  async getAgentsSummary(): Promise<AxiosResponse<any>> {
    return this.client.get('/api/agents/summary');
  }

  async getAgentDashboard(): Promise<AxiosResponse<{ summary: any; online_agents: any[]; offline_count: number; total_agents: number }>> {
    return this.client.get('/api/agents/status/dashboard');
  }

  async getAgentUptime(hours = 24): Promise<AxiosResponse<any>> {
    return this.client.get('/api/analytics/report/agent-uptime', { params: { hours } });
  }

  async registerNotificationChannel(config: NotificationChannelConfig): Promise<AxiosResponse<{ status: string; channel: string }>> {
    return this.client.post('/api/soar/config/notification', config);
  }

  // YARA
  async getYARAEvents(params?: {
    limit?: number;
    host?: string;
    rule_name?: string;
    severity?: string;
  }): Promise<AxiosResponse<YARAEvent[]>> {
    return this.client.get('/api/logs/yara/events', { params });
  }

  async getYARAStats(): Promise<AxiosResponse<YARAStats>> {
    return this.client.get('/api/logs/yara/stats');
  }

  async ingestYARAEvents(events: any[]): Promise<AxiosResponse<{ status: string; events_ingested: number }>> {
    return this.client.post('/api/logs/yara/events', events);
  }

  // Log Sources / Heartbeat
  async getLogSources(): Promise<AxiosResponse<Array<{ hostname: string; source_type: string; status: string; timestamp: string }>>> {
    return this.client.get('/api/logs/sources');
  }

  async exportIncidentsCSV(): Promise<AxiosResponse<Blob>> {
    return this.client.get('/api/incidents/export/csv', { responseType: 'blob' });
  }

  async purgeAllData(): Promise<AxiosResponse<{ status: string; indices: string[] }>> {
    return this.client.delete('/api/logs/purge', { params: { confirm: true, include_incidents: true } });
  }

  // Health checks
  async checkHealth(): Promise<AxiosResponse<{ status: string }>> {
    return this.client.get('/health');
  }

  async checkServiceHealth(service: string): Promise<AxiosResponse<{ status: string; service: string }>> {
    return this.client.get(`/api/${service}/health`);
  }

  // Network Flows
  async getFlows(params?: {
    limit?: number;
    offset?: number;
    src_ip?: string;
    dst_ip?: string;
    protocol?: string;
    min_bytes?: number;
    sort_by?: string;
    sort_order?: string;
  }): Promise<AxiosResponse<FlowRecord[]>> {
    return this.client.get('/api/flows/', { params });
  }

  async getFlowStats(): Promise<AxiosResponse<FlowStats>> {
    return this.client.get('/api/flows/stats');
  }

  // ── Case workbench (timeline / notes / lifecycle / exports) ──
  async getIncidentById(id: string): Promise<AxiosResponse<Incident>> {
    return this.client.get(`/api/incidents/${id}`);
  }

  async transitionIncident(id: string, status: Incident['status'], reason?: string): Promise<AxiosResponse> {
    return this.client.post(`/api/incidents/${id}/update`, { status, reason });
  }

  async addIncidentNote(id: string, body: string, author = 'analyst'): Promise<AxiosResponse<{ status: string; note: any }>> {
    return this.client.post(`/api/incidents/${id}/notes`, { body, author });
  }

  async getIncidentTimeline(id: string): Promise<AxiosResponse<{ incident_id: string; timeline: any[] }>> {
    return this.client.get(`/api/incidents/${id}/timeline`);
  }

  async exportIncidentJira(id: string): Promise<AxiosResponse<any>> {
    return this.client.post(`/api/incidents/${id}/export/jira`);
  }

  async exportIncidentTheHive(id: string): Promise<AxiosResponse<any>> {
    return this.client.post(`/api/incidents/${id}/export/thehive`);
  }

  // ── Evidence locker (chain-of-custody, simple) ──
  async getEvidence(id: string): Promise<AxiosResponse<{ incident_id: string; legal_hold: boolean; evidence: any[] }>> {
    return this.client.get(`/api/incidents/${id}/evidence`);
  }

  async seizeEvidence(id: string, ev: { type: string; title: string; description?: string; sha256?: string; collector?: string; source_host?: string }): Promise<AxiosResponse<{ status: string; evidence: any }>> {
    return this.client.post(`/api/incidents/${id}/evidence`, ev);
  }

  async transferEvidence(id: string, evidenceId: string, to: string, reason?: string): Promise<AxiosResponse<{ status: string; evidence: any }>> {
    return this.client.post(`/api/incidents/${id}/evidence/${evidenceId}/transfer`, { to, reason });
  }

  async verifyEvidence(id: string, evidenceId: string): Promise<AxiosResponse<{ evidence_id: string; ok: boolean; verified_at: string | null }>> {
    return this.client.post(`/api/incidents/${id}/evidence/${evidenceId}/verify`);
  }

  async setLegalHold(id: string, legal_hold: boolean): Promise<AxiosResponse<{ incident_id: string; legal_hold: boolean }>> {
    return this.client.post(`/api/incidents/${id}/hold`, { legal_hold });
  }

  async getActiveHolds(): Promise<AxiosResponse<{ holds: string[]; count: number }>> {
    return this.client.get('/api/incidents/holds/active');
  }

  async getComplianceReport(framework?: string): Promise<AxiosResponse<any>> {
    return this.client.get(framework ? `/api/incidents/export/compliance/${framework}` : '/api/incidents/export/compliance');
  }

  // ── MITRE / Sigma (wired) ──
  async getMitreTechniques(): Promise<AxiosResponse<{ total: number; techniques: any[] }>> {
    return this.client.get('/api/correlation/rules/mitre/techniques');
  }

  async getSigmaCoverage(): Promise<AxiosResponse<any>> {
    return this.client.get('/api/correlation/sigma/coverage');
  }

  async deploySigmaYaml(yaml: string): Promise<AxiosResponse<{ status: string; rule: any }>> {
    return this.client.post('/api/correlation/sigma/deploy', { yaml });
  }

  // ── Audit (tamper-evident) ──
  async appendAudit(action: string, resource_type = '', resource_id = '', details: any = {}): Promise<AxiosResponse> {
    return this.client.post('/api/audit/append', { action, resource_type, resource_id, details });
  }

  async getAudit(limit = 200): Promise<AxiosResponse<{ total: number; entries: any[] }>> {
    return this.client.get('/api/audit/', { params: { limit } });
  }

  async verifyAudit(): Promise<AxiosResponse<{ ok: boolean; checked: number; total: number }>> {
    return this.client.get('/api/audit/verify');
  }

  // ── Backup / restore ──
  async listBackups(): Promise<AxiosResponse<any>> {
    return this.client.get('/api/backup/list');
  }

  async triggerBackup(): Promise<AxiosResponse<any>> {
    return this.client.post('/api/backup/trigger');
  }

  async restoreBackup(name: string, index = 'chaelsiem-logs-restore'): Promise<AxiosResponse<any>> {
    return this.client.post('/api/backup/restore', null, { params: { name, index } });
  }

  // ── AI Assistant (privacy-first co-pilot, human-in-loop, multi-provider) ──
  async aiHealth(): Promise<AxiosResponse<any>> {
    return this.client.get('/api/ai/health');
  }

  async aiProviders(): Promise<AxiosResponse<any>> {
    return this.client.get('/api/ai/providers');
  }

  async aiExplain(incident_id?: string, incident?: any, aiProvider?: string): Promise<AxiosResponse<any>> {
    return this.client.post('/api/ai/explain', { incident_id, incident }, { ...aiHeaders(aiProvider), timeout: 60000 });
  }

  async aiTriage(incident_id?: string, incident?: any, aiProvider?: string): Promise<AxiosResponse<any>> {
    return this.client.post('/api/ai/triage', { incident_id, incident }, { ...aiHeaders(aiProvider), timeout: 60000 });
  }

  async aiQuery(question: string, aiProvider?: string): Promise<AxiosResponse<any>> {
    return this.client.post('/api/ai/query', { question }, { ...aiHeaders(aiProvider), timeout: 60000 });
  }

  async aiChat(message: string, history?: Array<{ role: string; content: string }>, aiProvider?: string, incidentId?: string): Promise<AxiosResponse<any>> {
    return this.client.post('/api/ai/chat', { message, history: history || [], include_siem_context: true, incident_id: incidentId || undefined }, { ...aiHeaders(aiProvider), timeout: 90000 });
  }

  async aiHuntAssist(hypothesis: string, opts?: { technique?: string; ioc?: string; external_intel?: any }, aiProvider?: string): Promise<AxiosResponse<any>> {
    return this.client.post('/api/ai/hunt', { hypothesis, ...(opts || {}) }, { ...aiHeaders(aiProvider), timeout: 90000 });
  }

  async aiReport(incident_id?: string, incident?: any, aiProvider?: string): Promise<AxiosResponse<any>> {
    return this.client.post('/api/ai/report', { incident_id, incident }, { ...aiHeaders(aiProvider), timeout: 60000 });
  }
}

/** Pin a specific AI provider/model via header; 'auto' (default) = failover order. */
function aiHeaders(aiProvider?: string): any {
  return aiProvider && aiProvider !== 'auto' ? { headers: { 'X-AI-Provider': aiProvider } } : undefined;
}

export const apiService = new ApiService();
