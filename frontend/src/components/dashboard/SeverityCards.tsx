import { useNavigate } from 'react-router-dom';
import { AlertTriangle, AlertCircle, AlertOctagon, Info, TrendingUp, TrendingDown } from 'lucide-react';
import type { Summary } from '../../types';

interface SeverityCardsProps {
  summary: Summary;
  previousSummary?: Summary;
}

interface SeverityCardProps {
  severity: 'critical' | 'high' | 'medium' | 'low';
  count: number;
  delta?: number;
}

const severityConfig = {
  critical: {
    label: 'Critical',
    icon: AlertOctagon,
    color: 'text-red-400',
    bgColor: 'bg-red-500/10',
    borderColor: 'border-red-500/30',
    glowClass: 'glow-critical',
  },
  high: {
    label: 'High',
    icon: AlertTriangle,
    color: 'text-orange-400',
    bgColor: 'bg-orange-500/10',
    borderColor: 'border-orange-500/30',
    glowClass: 'glow-high',
  },
  medium: {
    label: 'Medium',
    icon: AlertCircle,
    color: 'text-yellow-400',
    bgColor: 'bg-yellow-500/10',
    borderColor: 'border-yellow-500/30',
    glowClass: 'glow-medium',
  },
  low: {
    label: 'Low',
    icon: Info,
    color: 'text-blue-400',
    bgColor: 'bg-blue-500/10',
    borderColor: 'border-blue-500/30',
    glowClass: 'glow-low',
  },
};

function SeverityCard({ severity, count, delta = 0 }: SeverityCardProps) {
  const navigate = useNavigate();
  const config = severityConfig[severity];
  const Icon = config.icon;
  const isPositive = delta <= 0; // For security, less findings is better

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => navigate(`/findings?severity=${severity}`)}
      onKeyDown={(e) => e.key === 'Enter' && navigate(`/findings?severity=${severity}`)}
      className={`bg-[#121826] rounded-xl p-5 border ${config.borderColor} ${count > 0 ? config.glowClass : ''} transition-glow hover:translate-y-[-2px] cursor-pointer`}
    >
      <div className="flex items-start justify-between mb-4">
        <div className={`w-10 h-10 rounded-lg ${config.bgColor} flex items-center justify-center`}>
          <Icon className={`w-5 h-5 ${config.color}`} />
        </div>
        {delta !== 0 && (
          <div className={`flex items-center gap-1 text-xs font-medium ${
            isPositive ? 'text-green-400' : 'text-red-400'
          }`}>
            {isPositive ? (
              <TrendingDown className="w-3 h-3" />
            ) : (
              <TrendingUp className="w-3 h-3" />
            )}
            <span>{delta > 0 ? '+' : ''}{delta}</span>
          </div>
        )}
      </div>

      <div className="space-y-1">
        <p className={`text-4xl font-bold tabular-nums ${count > 0 ? config.color : 'text-slate-500'}`}>
          {count}
        </p>
        <p className="text-sm text-slate-400">{config.label}</p>
      </div>
    </div>
  );
}

export function SeverityCards({ summary, previousSummary }: SeverityCardsProps) {
  const getDelta = (current: number, previous?: number) => {
    if (previous === undefined) return 0;
    return current - previous;
  };

  return (
    <div className="grid grid-cols-4 gap-4">
      <SeverityCard 
        severity="critical" 
        count={summary.critical} 
        delta={getDelta(summary.critical, previousSummary?.critical)}
      />
      <SeverityCard 
        severity="high" 
        count={summary.high} 
        delta={getDelta(summary.high, previousSummary?.high)}
      />
      <SeverityCard 
        severity="medium" 
        count={summary.medium} 
        delta={getDelta(summary.medium, previousSummary?.medium)}
      />
      <SeverityCard 
        severity="low" 
        count={summary.low} 
        delta={getDelta(summary.low, previousSummary?.low)}
      />
    </div>
  );
}
