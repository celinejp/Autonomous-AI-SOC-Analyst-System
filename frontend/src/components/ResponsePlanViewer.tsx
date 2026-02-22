'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ResponsePlan, ResponseAction } from '@/types';
import { CheckCircle2, Clock, AlertCircle, Users } from 'lucide-react';

interface ResponsePlanViewerProps {
  plan: ResponsePlan;
  onActionUpdate?: (actionId: string, status: string) => void;
}

export function ResponsePlanViewer({ plan, onActionUpdate }: ResponsePlanViewerProps) {
  const immediate = plan.immediate_actions?.length ? plan.immediate_actions : (plan.containment_actions || []);
  const shortTerm = plan.short_term_actions?.length ? plan.short_term_actions : (plan.investigation_steps || []);
  const longTerm = plan.long_term_actions?.length ? plan.long_term_actions : (plan.remediation_actions || []).concat(plan.long_term_improvements || []);
  const allActions: Array<ResponseAction & { priority: string }> = [
    ...immediate.map((a: ResponseAction) => ({ ...a, priority: 'immediate' })),
    ...shortTerm.map((a: ResponseAction) => ({ ...a, priority: 'short_term' })),
    ...longTerm.map((a: ResponseAction) => ({ ...a, priority: 'long_term' })),
  ];

  const getPriorityIcon = (priority: string) => {
    switch (priority) {
      case 'immediate':
        return <AlertCircle className="h-4 w-4 text-red-400" />;
      case 'short_term':
        return <Clock className="h-4 w-4 text-yellow-400" />;
      case 'long_term':
        return <CheckCircle2 className="h-4 w-4 text-blue-400" />;
      default:
        return <Clock className="h-4 w-4 text-gray-400" />;
    }
  };

  const getPriorityLabel = (priority: string) => {
    switch (priority) {
      case 'immediate':
        return 'Immediate (<1h)';
      case 'short_term':
        return 'Short-term (1-24h)';
      case 'long_term':
        return 'Long-term (>24h)';
      default:
        return priority;
    }
  };

  const actionsByTeam = plan.actions_by_team || {};
  const teams = Object.keys(actionsByTeam);

  return (
    <div className="space-y-6">
      {/* Actions by Priority */}
      <div className="space-y-4">
        {['immediate', 'short_term', 'long_term'].map((priority) => {
          const actions = allActions.filter(a => a.priority === priority);
          if (actions.length === 0) return null;

          return (
            <Card key={priority} className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-white text-lg flex items-center space-x-2">
                  {getPriorityIcon(priority)}
                  <span>{getPriorityLabel(priority)} Actions</span>
                  <Badge variant="secondary">{actions.length}</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {actions.map((action, idx) => (
                    <div key={idx} className="p-4 bg-gray-800 rounded-lg">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex-1">
                          <h4 className="font-semibold text-white mb-1">{action.description}</h4>
                          <p className="text-sm text-gray-400">{action.action}</p>
                          <div className="flex items-center space-x-4 mt-2 text-xs text-gray-500">
                            <span className="flex items-center space-x-1">
                              <Users className="h-3 w-3" />
                              <span>{action.assigned_team}</span>
                            </span>
                            {action.sla_hours && (
                              <span>SLA: {action.sla_hours}h</span>
                            )}
                            {action.automated && (
                              <Badge variant="outline" className="text-xs">Automated</Badge>
                            )}
                            {action.requires_approval && (
                              <Badge variant="outline" className="text-xs">Requires Approval</Badge>
                            )}
                          </div>
                        </div>
                        <Badge variant="outline" className="ml-4">
                          {action.status || 'pending'}
                        </Badge>
                      </div>
                      {action.status === 'pending' && onActionUpdate && action.id && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => onActionUpdate(action.id, 'in_progress')}
                          className="mt-2"
                        >
                          Start Action
                        </Button>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Actions by Team */}
      {teams.length > 0 && (
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white">Actions by Team</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {teams.map((team) => (
                <div key={team}>
                  <h4 className="font-semibold text-white mb-2 flex items-center space-x-2">
                    <Users className="h-4 w-4" />
                    <span>{team}</span>
                    <Badge variant="secondary">{(actionsByTeam[team] || []).length}</Badge>
                  </h4>
                  <div className="space-y-2 pl-6">
                    {(actionsByTeam[team] || []).map((action: ResponseAction, idx: number) => (
                      <div key={idx} className="p-2 bg-gray-800 rounded text-sm">
                        <p className="text-white">{action.description}</p>
                        <p className="text-gray-400 text-xs mt-1">Status: {action.status || 'pending'}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

