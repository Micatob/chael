import { io, Socket } from 'socket.io-client';

class WebSocketService {
  private socket: Socket | null = null;
  private listeners: Map<string, Set<(data: any) => void>> = new Map();
  private retried = 0;
  private readonly maxRetries = 5;

  connect(token?: string): void {
    if (this.socket?.connected) return;

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}`;

    // Reuse existing socket if one is already created but disconnected
    if (this.socket) {
      try { this.socket.connect(); } catch { /* noop */ }
      return;
    }

    this.socket = io(wsUrl, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: this.maxRetries,
      reconnectionDelay: 3000,
      timeout: 5000,
      auth: { token },
    });

    this.socket.on('connect', () => {
      this.retried = 0;
    });

    this.socket.on('disconnect', () => {});

    // Back off quietly when no socket.io server exists (gateway only has
    // raw WS at /api/logs/ws) — polling fallback keeps pages live.
    this.socket.on('connect_error', () => {
      this.retried += 1;
      if (this.retried >= this.maxRetries) {
        this.socket?.disconnect();
      }
    });

    this.socket.on('log:ingested', (data) => this.emit('log:ingested', data));
    this.socket.on('incident:created', (data) => this.emit('incident:created', data));
    this.socket.on('correlation:alert', (data) => this.emit('correlation:alert', data));
    this.socket.on('soar:action', (data) => this.emit('soar:action', data));
    this.socket.on('agent:status', (data) => this.emit('agent:status', data));
    this.socket.on('agent:heartbeat', (data) => this.emit('agent:heartbeat', data));
  }

  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }

  on<T>(event: string, callback: (data: T) => void): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(callback);
  }

  off<T>(event: string, callback: (data: T) => void): void {
    this.listeners.get(event)?.delete(callback);
  }

  private emit(event: string, data: any): void {
    this.listeners.get(event)?.forEach((callback) => {
      try {
        callback(data);
      } catch (error) {
        console.error(`Error in WebSocket event handler for ${event}:`, error);
      }
    });
  }

  isConnected(): boolean {
    return this.socket?.connected ?? false;
  }
}

export const wsService = new WebSocketService();
