import { useEffect } from 'react';
import { useUIStore } from '../stores';

export function Toaster() {
  const { notifications, removeNotification } = useUIStore();

  useEffect(() => {
    notifications.forEach((notification) => {
      const timer = setTimeout(() => {
        removeNotification(notification.id);
      }, 5000);

      return () => clearTimeout(timer);
    });
  }, [notifications, removeNotification]);

  return (
    <div className="fixed top-4 right-4 z-50 space-y-2">
      {notifications.map((notification) => (
        <div
          key={notification.id}
          className={`glass-panel px-4 py-3 min-w-80 border-l-4 ${
            notification.type === 'error'
              ? 'border-severity-CRITICAL'
              : notification.type === 'warning'
              ? 'border-severity-HIGH'
              : notification.type === 'success'
              ? 'border-severity-LOW'
              : 'border-cyber-accent'
          } animate-fade-in`}
        >
          <p className="text-sm">{notification.message}</p>
        </div>
      ))}
    </div>
  );
}
