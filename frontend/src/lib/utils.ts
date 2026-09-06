import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(dateString: string | Date): string {
  const date = typeof dateString === 'string' ? new Date(dateString) : dateString;
  return new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

export function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: 'bg-red-500 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-500 text-white',
    low: 'bg-blue-500 text-white',
  };
  return colors[severity.toLowerCase()] || 'bg-gray-500 text-white';
}

// Simple notification system
let notificationCallbacks: ((message: string, type: 'success' | 'error' | 'info') => void)[] = [];

export function showNotification(message: string, type: 'success' | 'error' | 'info' = 'info') {
  notificationCallbacks.forEach(cb => cb(message, type));
}

export function onNotification(callback: (message: string, type: 'success' | 'error' | 'info') => void) {
  notificationCallbacks.push(callback);
  return () => {
    notificationCallbacks = notificationCallbacks.filter(cb => cb !== callback);
  };
}
