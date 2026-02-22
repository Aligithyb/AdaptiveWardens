import { Clock, Activity, AlertTriangle, Target, TrendingUp, Users } from 'lucide-react';

export function MetricsStats() {
  const metrics = [
    {
      label: 'Avg Session Length',
      value: '8m 34s',
      change: '+12%',
      trend: 'up',
      icon: Clock,
      color: 'cyan'
    },
    {
      label: 'Commands Per Session',
      value: '47',
      change: '+8%',
      trend: 'up',
      icon: Activity,
      color: 'green'
    },
    {
      label: 'Time to Detection',
      value: '23s',
      change: '-18%',
      trend: 'down',
      icon: Target,
      color: 'purple'
    },
    {
      label: 'Threat Actors',
      value: '156',
      change: '+24%',
      trend: 'up',
      icon: Users,
      color: 'orange'
    },
    {
      label: 'Total Sessions Today',
      value: '1,247',
      change: '+15%',
      trend: 'up',
      icon: TrendingUp,
      color: 'blue'
    },
    {
      label: 'High-Risk Sessions',
      value: '89',
      change: '+32%',
      trend: 'up',
      icon: AlertTriangle,
      color: 'red'
    },
  ];

  const getColorClasses = (color: string) => {
    switch (color) {
      case 'cyan': return { bg: 'bg-cyan-500/10', border: 'border-cyan-500/20', text: 'text-cyan-400', icon: 'text-cyan-400' };
      case 'green': return { bg: 'bg-green-500/10', border: 'border-green-500/20', text: 'text-green-400', icon: 'text-green-400' };
      case 'purple': return { bg: 'bg-purple-500/10', border: 'border-purple-500/20', text: 'text-purple-400', icon: 'text-purple-400' };
      case 'orange': return { bg: 'bg-orange-500/10', border: 'border-orange-500/20', text: 'text-orange-400', icon: 'text-orange-400' };
      case 'blue': return { bg: 'bg-blue-500/10', border: 'border-blue-500/20', text: 'text-blue-400', icon: 'text-blue-400' };
      case 'red': return { bg: 'bg-red-500/10', border: 'border-red-500/20', text: 'text-red-400', icon: 'text-red-400' };
      default: return { bg: 'bg-slate-500/10', border: 'border-slate-500/20', text: 'text-slate-400', icon: 'text-slate-400' };
    }
  };

  return (
    <div className="grid grid-cols-6 gap-4">
      {metrics.map((metric, idx) => {
        const Icon = metric.icon;
        const colors = getColorClasses(metric.color);
        const isPositive = metric.trend === 'up' && metric.label !== 'High-Risk Sessions';
        const isNegative = metric.trend === 'up' && metric.label === 'High-Risk Sessions';
        const isGood = metric.trend === 'down' && metric.label === 'Time to Detection';

        return (
          <div
            key={idx}
            className={`bg-slate-900 border ${colors.border} rounded-lg p-4 hover:${colors.bg} transition-colors`}
          >
            <div className="flex items-center justify-between mb-3">
              <div className={`w-10 h-10 ${colors.bg} rounded-lg flex items-center justify-center`}>
                <Icon className={`w-5 h-5 ${colors.icon}`} />
              </div>
              <span className={`text-xs ${
                isGood || (isPositive && !isNegative) ? 'text-green-400' : 
                isNegative ? 'text-red-400' : 
                'text-yellow-400'
              }`}>
                {metric.change}
              </span>
            </div>
            <div className={`text-2xl ${colors.text} mb-1`}>
              {metric.value}
            </div>
            <div className="text-xs text-slate-500">
              {metric.label}
            </div>
          </div>
        );
      })}
    </div>
  );
}
