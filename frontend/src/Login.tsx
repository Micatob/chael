import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Eye, EyeOff } from 'lucide-react';

const Login: React.FC = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const apiBase = (import.meta as any).env?.VITE_API_URL || '';

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            const response = await fetch(`${apiBase}/api/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({
                    username,
                    password
                })
            });

            if (response.ok) {
                const data = await response.json();
                const token = data.access_token;
                if (!token) {
                    setError('Authentication failed: no token received.');
                    return;
                }
                localStorage.setItem('s2_token', token);
                window.dispatchEvent(new Event('authchange'));
                navigate('/dashboard');
            } else {
                const errData = await response.json().catch(() => ({}));
                setError(errData.detail || 'Authentication failed. Please check credentials.');
            }
        } catch (err) {
            setError('Identity Service Unreachable. Check backend status.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center p-4" style={{ background: '#0a0a0a' }}>
            <div className="max-w-md w-full rounded-lg p-8" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)' }}>
                <div className="mb-8 text-center">
                    <h1 className="text-xl font-bold tracking-widest uppercase" style={{ color: '#d1d5db' }}>
                        Enterprise Security Intelligence
                    </h1>
                    <div className="mt-4" style={{ borderTop: '1px solid rgba(75,85,99,0.2)' }}></div>
                </div>

                <form onSubmit={handleLogin} className="space-y-6">
                    <div>
                        <label className="block text-xs font-bold uppercase mb-2" style={{ color: '#9ca3af' }}>
                            Username
                        </label>
                        <input
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            placeholder="admin"
                            required
                            className="w-full px-4 py-3 rounded text-sm font-bold placeholder-slate-600 focus:outline-none transition-all"
                            style={{ background: '#0a0a0a', border: '1px solid rgba(75,85,99,0.3)', color: '#d1d5db' }}
                        />
                    </div>

                    <div>
                        <label className="block text-xs font-bold uppercase mb-2" style={{ color: '#9ca3af' }}>
                            Password
                        </label>
                        <div className="relative">
                            <input
                                type={showPassword ? 'text' : 'password'}
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="Enter your password"
                                required
                                className="w-full px-4 py-3 pr-10 rounded text-sm font-bold placeholder-slate-600 focus:outline-none transition-all"
                                style={{ background: '#0a0a0a', border: '1px solid rgba(75,85,99,0.3)', color: '#d1d5db' }}
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                className="absolute right-3 top-1/2 -translate-y-1/2 p-1 rounded transition-colors"
                                style={{ color: '#6b7280' }}
                                onMouseEnter={e => { e.currentTarget.style.color = '#d1d5db'; }}
                                onMouseLeave={e => { e.currentTarget.style.color = '#6b7280'; }}
                            >
                                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                        </div>
                    </div>

                    {error && (
                        <div className="text-xs text-center p-2 rounded" style={{ color: '#ef4444', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)' }}>
                            {error}
                        </div>
                    )}

                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full disabled:cursor-not-allowed font-bold py-3 px-4 rounded transition-colors uppercase text-sm tracking-widest"
                        style={{ background: loading ? 'rgba(75,85,99,0.3)' : 'rgba(75,85,99,0.2)', border: '1px solid rgba(75,85,99,0.3)', color: loading ? '#6b7280' : '#d1d5db' }}
                    >
                        {loading ? 'Authenticating...' : 'Initiate Session'}
                    </button>
                </form>

                <div className="mt-8 pt-6 text-[10px] flex justify-between" style={{ borderTop: '1px solid rgba(75,85,99,0.2)', color: '#6b7280' }}>
                    <div>
                        SEC-ENCLAVE ID: <span style={{ color: '#9ca3af' }}>2948-AX-99</span>
                    </div>
                    <div>
                        AUTHORIZED PERSONNEL ONLY
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Login;
