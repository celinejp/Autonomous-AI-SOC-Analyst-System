'use client';

import { useState, useEffect } from 'react';
import { showNotification, onNotification } from '@/lib/utils';
import { CheckCircle2, XCircle, Info, X } from 'lucide-react';

interface NotificationState {
  id: number;
  message: string;
  type: 'success' | 'error' | 'info';
}

let notificationId = 0;

export function NotificationContainer() {
  const [notifications, setNotifications] = useState<NotificationState[]>([]);

  useEffect(() => {
    const unsubscribe = onNotification((message, type) => {
      const id = ++notificationId;
      setNotifications(prev => [...prev, { id, message, type }]);
      
      // Auto-remove after 5 seconds
      setTimeout(() => {
        setNotifications(prev => prev.filter(n => n.id !== id));
      }, 5000);
    });

    return unsubscribe;
  }, []);

  const removeNotification = (id: number) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  };

  if (notifications.length === 0) return null;

  return (
    <div className="fixed top-4 right-4 z-50 space-y-2">
      {notifications.map((notification) => {
        const icons = {
          success: <CheckCircle2 className="h-5 w-5 text-green-400" />,
          error: <XCircle className="h-5 w-5 text-red-400" />,
          info: <Info className="h-5 w-5 text-blue-400" />,
        };

        const bgColors = {
          success: 'bg-green-900/20 border-green-500/50',
          error: 'bg-red-900/20 border-red-500/50',
          info: 'bg-blue-900/20 border-blue-500/50',
        };

        const textColors = {
          success: 'text-green-400',
          error: 'text-red-400',
          info: 'text-blue-400',
        };

        return (
          <div
            key={notification.id}
            className={`p-4 rounded-lg border ${bgColors[notification.type]} backdrop-blur-sm min-w-[300px] max-w-md animate-in slide-in-from-right`}
          >
            <div className="flex items-start space-x-3">
              {icons[notification.type]}
              <div className="flex-1">
                <p className={`font-medium ${textColors[notification.type]}`}>
                  {notification.message}
                </p>
              </div>
              <button
                onClick={() => removeNotification(notification.id)}
                className="text-gray-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}

