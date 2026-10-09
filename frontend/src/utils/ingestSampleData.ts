import axios from 'axios';
import { NormalizedLog } from '../types';

const API_BASE_URL = 'http://localhost:8000/api';

const sampleLogs: NormalizedLog[] = [
  {
    timestamp: new Date().toISOString(),
    host: 'web-server-01',
    source: 'nginx',
    log_type: 'access',
    severity: 'INFO',
    message: 'GET /api/dashboard 200 45ms',
    metadata: { user_agent: 'Mozilla/5.0', ip: '192.168.1.100' },
  },
  {
    timestamp: new Date(Date.now() - 60000).toISOString(),
    host: 'db-server-02',
    source: 'postgresql',
    log_type: 'error',
    severity: 'HIGH',
    message: 'Connection timeout to replica',
    metadata: { error_code: 'ETIMEDOUT', db_name: 'siem_db' },
  },
  {
    timestamp: new Date(Date.now() - 120000).toISOString(),
    host: 'auth-server-03',
    source: 'auth-service',
    log_type: 'security',
    severity: 'CRITICAL',
    message: 'Failed login attempt from unknown IP',
    metadata: { username: 'admin', ip: '10.0.0.5', attempts: 5 },
    incident_id: 'inc-001',
  },
  {
    timestamp: new Date(Date.now() - 180000).toISOString(),
    host: 'api-gateway-04',
    source: 'kong',
    log_type: 'access',
    severity: 'LOW',
    message: 'Rate limit exceeded for API key xyz123',
    metadata: { api_key: 'xyz123', limit: 1000 },
  },
  {
    timestamp: new Date(Date.now() - 240000).toISOString(),
    host: 'monitoring-05',
    source: 'prometheus',
    log_type: 'metric',
    severity: 'MEDIUM',
    message: 'CPU usage spike to 95%',
    metadata: { cpu_percent: 95, threshold: 80 },
  },
];

export async function ingestSampleData() {
  try {
    console.log('Starting sample data ingestion...');

    for (const log of sampleLogs) {
      try {
        const response = await axios.post(`${API_BASE_URL}/logs/ingest`, log, {
          headers: {
            'Content-Type': 'application/json',
            // Note: In a real scenario, you'd include auth token
          },
        });
        console.log(`Ingested log: ${log.message} - Status: ${response.status}`);
      } catch (error) {
        console.error(`Failed to ingest log: ${log.message}`, error);
      }
    }

    console.log('Sample data ingestion completed.');
  } catch (error) {
    console.error('Error during sample data ingestion:', error);
  }
}
