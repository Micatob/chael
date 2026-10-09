import { ReactNode } from 'react';

interface CardProps {
  children: ReactNode;
  className?: string;
}

export function Card({ children, className = '' }: CardProps) {
  return (
    <div className={`glass-panel p-6 ${className}`}>
      {children}
    </div>
  );
}

interface StatCardProps {
  title: string;
  value: string | number;
  icon: ReactNode;
  trend?: { value: number; label: string };
}

export function StatCard({ title, value, icon, trend }: StatCardProps) {
  return (
    <Card className="relative overflow-hidden">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-cyber-muted mb-1">{title}</p>
          <p className="text-3xl font-bold text-cyber-accent">{value}</p>
          {trend && (
            <p className={`text-xs mt-2 ${trend.value >= 0 ? 'text-severity-LOW' : 'text-severity-CRITICAL'}`}>
              {trend.value >= 0 ? '+' : ''}{trend.value}% {trend.label}
            </p>
          )}
        </div>
        <div className="text-cyber-muted">{icon}</div>
      </div>
    </Card>
  );
}

interface ButtonProps {
  children: ReactNode;
  onClick?: (e?: React.MouseEvent) => void;
  variant?: 'primary' | 'secondary' | 'danger';
  className?: string;
  disabled?: boolean;
  type?: 'button' | 'submit' | 'reset';
}

export function Button({ children, onClick, variant = 'primary', className = '', disabled }: ButtonProps) {
  const variants = {
    primary: 'cyber-button',
    secondary: 'bg-cyber-border text-cyber-bg hover:bg-cyber-muted',
    danger: 'bg-severity-CRITICAL text-cyber-bg hover:bg-red-600',
  };

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`${variants[variant]} ${className} disabled:opacity-50 disabled:cursor-not-allowed`}
    >
      {children}
    </button>
  );
}

interface BadgeProps {
  children: ReactNode;
  variant?: 'severity-critical' | 'severity-high' | 'severity-medium' | 'severity-low' | 'info';
}

export function Badge({ children, variant = 'info' }: BadgeProps) {
  const variants = {
    'severity-critical': 'severity-critical',
    'severity-high': 'severity-high',
    'severity-medium': 'severity-medium',
    'severity-low': 'severity-low',
    info: 'bg-cyber-muted text-cyber-bg',
  };

  return <span className={`${variants[variant]} px-2 py-1 rounded text-xs`}>{children}</span>;
}
