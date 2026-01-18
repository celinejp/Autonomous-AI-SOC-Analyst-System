import { useMutation } from '@tanstack/react-query';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';

export function useAnalyzeLogs() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (logs: string[]) => api.ingest.analyze(logs),
    onSuccess: (data) => {
      // Invalidate incidents list to show new incident
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard', 'stats'] });
    },
  });
}

