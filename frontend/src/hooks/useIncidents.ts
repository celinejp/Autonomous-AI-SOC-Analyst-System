import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { Incident } from '@/types';

interface UseIncidentsParams {
  status?: string;
  severity?: string;
  limit?: number;
  offset?: number;
}

export function useIncidents(params: UseIncidentsParams = {}) {
  return useQuery<Incident[]>({
    queryKey: ['incidents', params],
    queryFn: () => api.incidents.list(params),
    placeholderData: [],
    staleTime: 30000, // 30 seconds
  });
}

