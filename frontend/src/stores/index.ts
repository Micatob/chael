import { create } from 'zustand';
import { NormalizedLog, Incident } from '../types';

interface LogState {
  logs: NormalizedLog[];
  loading: boolean;
  error: string | null;
  addLog: (log: NormalizedLog) => void;
  setLogs: (logs: NormalizedLog[]) => void;
  clearLogs: () => void;
}

export const useLogStore = create<LogState>((set) => ({
  logs: [],
  loading: false,
  error: null,
  addLog: (log) => set((state) => ({ logs: [log, ...state.logs].slice(0, 1000) })),
  setLogs: (logs) => set({ logs }),
  clearLogs: () => set({ logs: [] }),
}));

interface IncidentState {
  incidents: Incident[];
  selectedIncident: Incident | null;
  loading: boolean;
  error: string | null;
  setIncidents: (incidents: Incident[]) => void;
  addIncident: (incident: Incident) => void;
  updateIncident: (id: string, updates: Partial<Incident>) => void;
  selectIncident: (incident: Incident | null) => void;
  clearIncidents: () => void;
}

export const useIncidentStore = create<IncidentState>((set) => ({
  incidents: [],
  selectedIncident: null,
  loading: false,
  error: null,
  setIncidents: (incidents) => set({ incidents }),
  addIncident: (incident) =>
    set((state) => ({
      incidents: [incident, ...state.incidents.filter((i) => i.incident_id !== incident.incident_id)],
    })),
  updateIncident: (id, updates) =>
    set((state) => ({
      incidents: state.incidents.map((inc) =>
        inc.incident_id === id ? { ...inc, ...updates } : inc
      ),
      selectedIncident:
        state.selectedIncident?.incident_id === id
          ? { ...state.selectedIncident, ...updates }
          : state.selectedIncident,
    })),
  selectIncident: (incident) => set({ selectedIncident: incident }),
  clearIncidents: () => set({ incidents: [], selectedIncident: null }),
}));

interface UIState {
  sidebarOpen: boolean;
  notifications: Array<{ id: string; type: 'info' | 'warning' | 'error' | 'success'; message: string }>;
  addNotification: (notification: { type: 'info' | 'warning' | 'error' | 'success'; message: string }) => void;
  removeNotification: (id: string) => void;
  toggleSidebar: () => void;
  closeSidebar: () => void;
}

export const useUIStore = create<UIState>((set) => ({
  sidebarOpen: true,
  notifications: [],
  addNotification: (notification) =>
    set((state) => ({
      notifications: [
        ...state.notifications,
        { ...notification, id: Date.now().toString() },
      ].slice(-5),
    })),
  removeNotification: (id) =>
    set((state) => ({
      notifications: state.notifications.filter((n) => n.id !== id),
    })),
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  closeSidebar: () => set({ sidebarOpen: false }),
}));

interface AuthState {
  user: any | null;
  isAuthenticated: boolean;
  login: (user: any) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: !!localStorage.getItem('s2_token'),
  login: (user) => set({ user, isAuthenticated: true }),
  logout: () => {
    localStorage.removeItem('s2_token');
    set({ user: null, isAuthenticated: false });
  },
}));
