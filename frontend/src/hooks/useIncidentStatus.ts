import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { Incident, IncidentStatus } from '@/types';

export function useIncidentStatus(incidentId: string) {
  return useQuery<Incident>({
    queryKey: ['incident-status', incidentId],
    queryFn: () => api.incidents.get(incidentId),
    enabled: !!incidentId,
    refetchInterval: (query) => {
      // Stop polling if incident is resolved or analyzing is complete
      const incident = query.state.data as Incident | undefined;
      if (incident?.status === IncidentStatus.RESOLVED || 
          incident?.status === IncidentStatus.FALSE_POSITIVE) {
        return false;
      }
      return 5000; // Poll every 5 seconds while analyzing
    },
  });
}

