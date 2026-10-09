// Core types
export interface NormalizedLog {
  timestamp: string;
  host: string;
  source: string;
  log_type: string;
  severity: Severity;
  message: string;
  metadata: Record<string, any>;
  incident_id?: string;
  original_log?: string;
}

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Incident {
  incident_id: string;
  timestamp: string;
  risk_score: number;
  source_logs: any[];
  status: IncidentStatus;
  description?: string;
  artifacts: Record<string, any>;
  pending_actions?: SOARAction[];
  investigation_results?: InvestigationResult;
  mitigation_history?: any[];
  notes?: Array<{ note_id: string; author: string; body: string; created_at: string; visibility: string }>;
  timeline?: Array<{ timestamp: string; actor: string; action: string; details: Record<string, any> }>;
  evidence?: EvidenceItem[];
  legal_hold?: boolean;
}

export interface EvidenceItem {
  evidence_id: string;
  type: string;
  title: string;
  description: string;
  sha256: string;
  collector: string;
  source_host: string;
  created_at: string;
  custody: Array<{ timestamp: string; from: string; to: string; reason: string; actor: string }>;
  verified: boolean;
  verified_at: string | null;
  seal_hash?: string;
}

export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';

export interface SOARAction {
  action_id: string;
  name: string;
  params: Record<string, any>;
  status: SOARActionStatus;
  created_at: string;
}

export type SOARActionStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXECUTED' | 'FAILED';

export interface Asset {
  hostname: string;
  role: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  reference: string;
}

export interface ExtractedIndicators {
  ip_addresses: string[];
  usernames: string[];
  cve_ids: string[];
  file_paths: string[];
}

export interface InvestigationResult {
  incident_id: string;
  analysis_timestamp: string;
  severity_assessment: string;
  attack_classification?: string;
  mitre_technique?: MitreTechnique;
  indicators_extracted?: ExtractedIndicators;
  affected_assets: Asset[];
  recommended_actions: string[];
  walkthrough: string[];
  follow_up_steps: string[];
  soc_verdict_guide?: string;
  false_positive_checklist?: string[];
  confidence_score: number;
  ioc_matches: IOCMatch[];
  threat_intel_enrichment?: Record<string, any>;
}

export interface IOCMatch {
  ioc: string;
  type: string;
  confidence: number;
  context?: string;
}

// API Response types
export interface ApiResponse<T = any> {
  status: string;
  data?: T;
  error?: string;
}

export interface LogStats {
  total_logs: number;
  ingestion_rate_per_hour: number;
  severity_distribution: Record<string, number>;
}

export interface AnalyticsOverview {
  total_logs_24h: number;
  active_incidents: number;
  system_status: string;
  ingestion_trend: Array<{ name: string; logs: number }>;
}

// Auth types
export interface LoginCredentials {
  username: string;
  password: string;
}

export interface User {
  id: string;
  username: string;
  role: string;
  permissions: string[];
}

// Threat Feed (IOC) types
export interface IOCItem {
  ioc_id?: string;
  type: IOCType;
  value: string;
  description?: string;
  source?: string;
  confidence?: IOCConfidence;
  tags?: string[];
  created_at?: string;
  expires_at?: string;
}

export type IOCType = 'IP_ADDRESS' | 'DOMAIN' | 'URL' | 'HASH_MD5' | 'HASH_SHA1' | 'HASH_SHA256';
export type IOCConfidence = 'low' | 'medium' | 'high';

export interface EnrichResult {
  matches: IOCItem[];
  total: number;
  [key: string]: any;
}

// SOAR types
export interface SOARHistoryEntry {
  action_id?: string;
  incident_id?: string;
  action?: string;
  status?: string;
  timestamp?: string;
  result?: any;
  [key: string]: any;
}

export interface PendingAction {
  action_id: string;
  name: string;
  params: Record<string, any>;
  status: string;
}

export interface NotificationChannelConfig {
  channel: string;
  enabled: boolean;
  config: Record<string, any>;
}

// Network Flow types
export interface FlowRecord {
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  bytes: number;
  packets: number;
  duration_seconds: number;
  src_host?: string;
  dst_host?: string;
  app_name?: string;
  direction: 'ingress' | 'egress' | 'unknown';
  metadata: Record<string, any>;
  tenant_id?: string;
}

export interface FlowStats {
  total_flows_24h: number;
  unique_src_ips: number;
  unique_dst_ips: number;
  total_bytes: number;
  total_megabytes: number;
  top_ports: Array<{ port: number; count: number }>;
  top_protocols: Array<{ protocol: string; count: number }>;
  top_src_ips: Array<{ ip: string; count: number }>;
  top_dst_ips: Array<{ ip: string; count: number }>;
}

// YARA types
export interface YARAEvent {
  timestamp: string;
  host: string;
  source: string;
  log_type: string;
  severity: string;
  message: string;
  metadata: {
    yara_rule_name: string;
    yara_rule_source: string;
    yara_file_path: string;
    yara_tags: string[];
    yara_strings: Array<{ identifier: string; offset: number; data: string }>;
    yara_meta: Record<string, any>;
    platform: string;
    hostname: string;
  };
}

export interface YARAStats {
  total_events: number;
  by_rule_name: Record<string, number>;
  by_host: Record<string, number>;
  by_severity: Record<string, number>;
}

// Log Source Heartbeat
export interface LogSource {
  hostname: string;
  source_type: string;
  status: string;
  timestamp: string;
}

// WebSocket events
export interface WSEvent {
  type: 'log:ingested' | 'incident:created' | 'correlation:alert' | 'soar:action';
  payload: any;
  timestamp: string;
}
