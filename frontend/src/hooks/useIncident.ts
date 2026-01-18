import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { Incident, IncidentStatus } from '@/types';

export function useIncident(id: string) {
  return useQuery<Incident>({
    queryKey: ['incident', id],
    queryFn: () => api.incidents.get(id),
    enabled: !!id,
    refetchInterval: (query) => {
      const incident = query.state.data as Incident | undefined;
      // Keep polling if analyzing or in progress
      if (incident?.status === IncidentStatus.IN_PROGRESS || 
          incident?.status === IncidentStatus.INVESTIGATING) {
        return 5000; // Poll every 5 seconds
      }
      return false;
    },
  });
}

