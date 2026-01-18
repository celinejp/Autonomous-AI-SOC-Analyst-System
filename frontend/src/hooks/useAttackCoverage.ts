import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

export function useAttackCoverage() {
  return useQuery({
    queryKey: ['attack-coverage'],
    queryFn: () => api.metrics.attackCoverage(),
    staleTime: 300000, // 5 minutes
  });
}

