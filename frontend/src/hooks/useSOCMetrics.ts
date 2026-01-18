import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { SOCMetrics } from '@/types';

export function useSOCMetrics(hours: number = 24) {
  return useQuery<SOCMetrics>({
    queryKey: ['soc-metrics', hours],
    queryFn: async () => {
      const response = await api.metrics.socKPIs(hours);
      return response.metrics || response;
    },
    staleTime: 60000, // 1 minute
    refetchInterval: 300000, // 5 minutes
  });
}

