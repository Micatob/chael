import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './Login';
import { Layout } from './components/Layout';
import Dashboard from './pages/Dashboard';
import { Logs } from './pages/Logs';
import { Incidents } from './pages/Incidents';
import Hunt from './pages/Hunt';
import Agents from './pages/Agents';
import SOAR from './pages/SOAR';
import YARA from './pages/YARA';
import AICopilot from './pages/AICopilot';
import { wsService } from './services/websocket';
import { useLogStore } from './stores';
import { useIncidentStore } from './stores';

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = React.useState(() => !!localStorage.getItem('s2_token'));
  const { addLog } = useLogStore();
  const { addIncident } = useIncidentStore();

  React.useEffect(() => {
    const checkAuth = () => setIsAuthenticated(!!localStorage.getItem('s2_token'));

    window.addEventListener('storage', checkAuth);
    window.addEventListener('authchange', checkAuth);

    return () => {
      window.removeEventListener('storage', checkAuth);
      window.removeEventListener('authchange', checkAuth);
    };
  }, []);

  React.useEffect(() => {
    if (isAuthenticated) {
      const token = localStorage.getItem('s2_token') || undefined;
      wsService.connect(token);

      wsService.on('log:ingested', (data: any) => {
        addLog(data);
      });

      wsService.on('incident:created', (data: any) => {
        addIncident(data);
      });
    } else {
      wsService.disconnect();
    }

    return () => {};
  }, [isAuthenticated, addLog, addIncident]);

  return (
    <Router>
      <Routes>
        <Route path="/login" element={isAuthenticated ? <Navigate to="/dashboard" /> : <Login />} />
        <Route element={isAuthenticated ? <Layout /> : <Navigate to="/login" />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/hunt" element={<Hunt />} />
          <Route path="/agents" element={<Agents />} />
          <Route path="/soar" element={<SOAR />} />
          <Route path="/yara" element={<YARA />} />
          <Route path="/ai-copilot" element={<AICopilot />} />
        </Route>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Router>
  );
};

export default App;