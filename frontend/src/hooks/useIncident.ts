import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { Incident, IncidentStatus } from '@/types';

export function useIncident(id: string) {
  return useQuery<Incident>({
    queryKey: ['incident', id],
    queryFn: async () => {
      try {
        return await api.incidents.get(id);
      } catch (error: any) {
        if (error?.message?.includes('404') || error?.message?.includes('Not Found')) {
          throw error;
        }
        throw error;
      }
    },
    enabled: !!id,
    retry: (failureCount, error: any) => {
      // Retry up to 10 times for 404 errors (incident might be creating)
      if (error?.message?.includes('404') || error?.message?.includes('Not Found')) {
        return failureCount < 10;
      }
      return failureCount < 3;
    },
    retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 5000), // Exponential backoff, max 5s
    refetchInterval: (query) => {
      const incident = query.state.data as Incident | undefined;
      const error = query.state.error as any;
      
      // If we have a 404 error, keep retrying
      if (error && (error?.message?.includes('404') || error?.message?.includes('Not Found'))) {
        return 2000; // Poll every 2 seconds until found
      }
      
      // Keep polling if analyzing or in progress
      if (incident?.status === IncidentStatus.IN_PROGRESS ||
          incident?.status === IncidentStatus.INVESTIGATING) {
        return 5000; // Poll every 5 seconds
      }
      return false;
    },
  });
}

