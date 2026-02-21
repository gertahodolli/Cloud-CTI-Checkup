import { useNavigate } from 'react-router-dom';
import { AlertOctagon, AlertTriangle, AlertCircle, Info, ChevronRight, Clock } from 'lucide-react';
import type { Finding, Severity } from '../../types';

interface RecentFindingsProps {
  findings: Finding[];
  limit?: number;
}

const severityIcons: Record<Severity, typeof AlertOctagon> = {
  critical: AlertOctagon,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Info,
  info: Info,
};

const severityColors: Record<Severity, string> = {
  critical: 'text-red-400 bg-red-500/10',
  high: 'text-orange-400 bg-orange-500/10',
  medium: 'text-yellow-400 bg-yellow-500/10',
  low: 'text-blue-400 bg-blue-500/10',
  info: 'text-slate-400 bg-slate-500/10',
};

function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  
  if (diffDays === 0) return 'Today';
  if (diffDays === 1) return 'Yesterday';
  if (diffDays < 7) return `${diffDays} days ago`;
  if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
  return `${Math.floor(diffDays / 30)} months ago`;
}

export function RecentFindings({ findings, limit = 5 }: RecentFindingsProps) {
  const navigate = useNavigate();
  
  // Sort by first_seen (most recent first) and limit
  const recentFindings = [...findings]
    .filter(f => f.finding_status === 'open')
    .sort((a, b) => new Date(b.first_seen).getTime() - new Date(a.first_seen).getTime())
    .slice(0, limit);

  return (
    <div className="bg-[#121826] rounded-xl border border-[#1E293B]">
      <div className="flex items-center justify-between p-5 border-b border-[#1E293B]">
        <h3 className="text-lg font-semibold text-slate-200">Recent Findings</h3>
        <button 
          onClick={() => navigate('/findings')}
          className="text-sm text-amber-500 hover:text-amber-400 font-medium transition-colors flex items-center gap-1"
        >
          View All
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>

      <div className="divide-y divide-[#1E293B]">
        {recentFindings.map((finding) => {
          const Icon = severityIcons[finding.severity];
          const colorClass = severityColors[finding.severity];
          
          return (
            <div 
              key={finding.finding_id}
              className="p-4 hover:bg-[#1a2233] cursor-pointer transition-colors group"
              onClick={() => navigate(`/findings?id=${finding.finding_id}`)}
            >
              <div className="flex items-start gap-3">
                <div className={`p-2 rounded-lg ${colorClass}`}>
                  <Icon className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-slate-200 line-clamp-1 group-hover:text-amber-400 transition-colors">
                    {finding.issue}
                  </p>
                  <div className="flex items-center gap-3 mt-1">
                    <span className="text-xs text-slate-500">{finding.service}</span>
                    <span className="text-xs text-slate-600">•</span>
                    <span className="text-xs text-slate-500">{finding.resource_id}</span>
                  </div>
                </div>
                <div className="flex items-center gap-1 text-xs text-slate-500">
                  <Clock className="w-3 h-3" />
                  <span>{formatTimeAgo(finding.first_seen)}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {recentFindings.length === 0 && (
        <div className="p-8 text-center">
          <p className="text-slate-500">No open findings</p>
        </div>
      )}
    </div>
  );
}
