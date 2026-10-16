import { useState } from 'react';
import { Link, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks';
import { LogOut, Menu, Shield, AlertTriangle, FileText, Monitor, Search, Zap, Crosshair, Bot } from 'lucide-react';

const navItems = [
  { path: '/dashboard', label: 'Dashboard', icon: Shield },
  { path: '/incidents', label: 'Incidents', icon: AlertTriangle },
  { path: '/logs', label: 'Logs', icon: FileText },
  { path: '/hunt', label: 'Hunt', icon: Search },
  { path: '/agents', label: 'Agents', icon: Monitor },
  { path: '/soar', label: 'SOAR', icon: Zap },
  { path: '/yara', label: 'YARA', icon: Crosshair },
  { path: '/ai-copilot', label: 'Chael AI', icon: Bot },
];

export function Layout() {
  const { logout } = useAuth();
  // Start collapsed on narrow screens so content gets the full width.
  const [sidebarOpen, setSidebarOpen] = useState(
    () => typeof window === 'undefined' || window.innerWidth >= 768,
  );
  const location = useLocation();
  const closeSidebar = () => setSidebarOpen(false);

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: '#0a0a0a', color: '#d1d5db' }}>
      {/* Mobile backdrop: tap outside to dismiss the overlay sidebar */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 md:hidden"
          style={{ background: 'rgba(0,0,0,0.6)' }}
          onClick={closeSidebar}
        />
      )}
      <aside
        className={`${sidebarOpen ? 'flex w-64' : 'hidden md:flex md:w-16'} transition-all duration-300 flex-col shrink-0 fixed md:static z-40 h-screen`}
        style={{ borderRight: '1px solid #333', background: '#111' }}
      >
        <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid #333' }}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: '#2563eb' }}>
              <Shield className="w-6 h-6" style={{ color: '#0a0a0a' }} />
            </div>
            {sidebarOpen && <span className="font-bold text-xl">Chael SIEM</span>}
          </div>
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-2 rounded"
            style={{ border: '1px solid #333', color: '#9ca3af', background: 'transparent' }}
          >
            <Menu className="w-4 h-4" />
          </button>
        </div>

        <nav className="flex-1 py-4 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                onClick={() => { if (typeof window !== 'undefined' && window.innerWidth < 768) closeSidebar(); }}
                className={`flex items-center gap-3 px-4 py-3 ${
                  sidebarOpen ? 'justify-start' : 'justify-center'
                }`}
                style={isActive
                  ? { background: 'rgba(96,165,250,0.2)', color: '#60a5fa', borderRight: '2px solid #60a5fa' }
                  : { color: '#9ca3af' }
                }
              >
                <Icon className="w-5 h-5" />
                {sidebarOpen && <span className="text-sm">{item.label}</span>}
              </Link>
            );
          })}
          <div className="my-2 mx-4" style={{ borderTop: '1px solid #333' }} />
        </nav>

        <div className="p-4" style={{ borderTop: '1px solid #333' }}>
          <button
            onClick={logout}
            className={`flex items-center gap-2 w-full ${sidebarOpen ? 'justify-start' : 'justify-center'} text-xs px-3 py-1.5 rounded`}
            style={{ border: '1px solid #333', color: '#9ca3af', background: 'transparent' }}
          >
            <LogOut className="w-4 h-4" />
            {sidebarOpen && <span className="ml-2">Logout</span>}
          </button>
        </div>
      </aside>

      <main className="flex-1 min-w-0 overflow-auto" style={{ background: '#0a0a0a' }}>
        <div className="p-4 md:p-6 max-w-full">
          {/* Mobile menu button (sidebar is hidden on small screens when closed) */}
          <button
            onClick={() => setSidebarOpen(true)}
            className={`${sidebarOpen ? 'hidden' : ''} md:hidden mb-3 p-2 rounded`}
            style={{ border: '1px solid #333', color: '#9ca3af', background: 'transparent' }}
            aria-label="Open menu"
          >
            <Menu className="w-4 h-4" />
          </button>
          <Outlet />
        </div>
      </main>
    </div>
  );
}
