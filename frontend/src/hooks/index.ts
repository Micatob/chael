import { useEffect, useState } from 'react';
import { NormalizedLog, Incident } from '../types';
import { apiService } from '../services/api';
import { wsService } from '../services/websocket';
import { useLogStore, useIncidentStore, useAuthStore } from '../stores';

export function useLogs() {
  const { logs, setLogs, addLog } = useLogStore();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchLogs = async (limit = 100, offset = 0) => {
    setLoading(true);
    try {
      const response = await apiService.getLogs(limit, offset);
      setLogs(response.data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  useEffect(() => {
    const token = localStorage.getItem('s2_token');
    wsService.connect(token ?? undefined);
    const handler = (log: NormalizedLog) => {
      addLog(log);
    };
    wsService.on<NormalizedLog>('log:ingested', handler);

    return () => {
      wsService.off('log:ingested', handler);
    };
  }, []);

  return { logs, loading, error, fetchLogs, addLog };
}

export function useIncidents() {
  const { incidents, setIncidents, addIncident, updateIncident, selectIncident } = useIncidentStore();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const response = await apiService.getIncidents();
      setIncidents(response.data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch incidents');
    } finally {
      setLoading(false);
    }
  };

  const createIncident = async (incident: Omit<Incident, 'incident_id'>) => {
    try {
      const response = await apiService.createIncident(incident);
      addIncident(response.data);
      return response.data;
    } catch (err) {
      throw err instanceof Error ? err : new Error('Failed to create incident');
    }
  };

  const investigate = async (id: string) => {
    try {
      const response = await apiService.investigateIncident(id);
      updateIncident(id, { investigation_results: response.data });
      return response.data;
    } catch (err) {
      throw err instanceof Error ? err : new Error('Failed to investigate');
    }
  };

  const resolveIncident = async (id: string, status: Incident['status'] = 'RESOLVED') => {
    try {
      await apiService.updateIncidentStatus(id, status);
      updateIncident(id, { status });
    } catch (err) {
      throw err instanceof Error ? err : new Error('Failed to update status');
    }
  };

  const mitigate = async (id: string, action: { action_type: string; target: string; reason: string }) => {
    try {
      const response = await apiService.mitigateIncident(id, action);
      updateIncident(id, { mitigation_history: [response.data] });
      return response.data;
    } catch (err) {
      throw err instanceof Error ? err : new Error('Mitigation failed');
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  useEffect(() => {
    const token = localStorage.getItem('s2_token');
    wsService.connect(token ?? undefined);
    const handler = (incident: Incident) => {
      addIncident(incident);
    };
    wsService.on<Incident>('incident:created', handler);

    return () => {
      wsService.off('incident:created', handler);
    };
  }, []);

  return {
    incidents,
    loading,
    error,
    fetchIncidents,
    createIncident,
    investigate,
    resolveIncident,
    mitigate,
    selectIncident,
    updateIncident,
  };
}

export function useAuth() {
  const { user, isAuthenticated, login, logout } = useAuthStore();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const performLogin = async (credentials: { username: string; password: string }) => {
    setLoading(true);
    try {
      const response = await apiService.login(credentials);
      login(response.data.user);
      localStorage.setItem('s2_token', 'dummy-jwt-token');
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const performLogout = () => {
    logout();
    apiService.logout().catch(() => {});
  };

  return { user, isAuthenticated, loading, error, login: performLogin, logout: performLogout };
}
