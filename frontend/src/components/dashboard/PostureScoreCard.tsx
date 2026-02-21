import { TrendingUp, TrendingDown, Shield } from 'lucide-react';

interface PostureScoreCardProps {
  score: number;
  previousScore?: number;
  maxScore?: number;
}

function getGrade(score: number): { label: string; color: string } {
  if (score >= 90) return { label: 'Excellent', color: 'text-green-400' };
  if (score >= 75) return { label: 'Good', color: 'text-emerald-400' };
  if (score >= 60) return { label: 'Fair', color: 'text-yellow-400' };
  if (score >= 40) return { label: 'Poor', color: 'text-orange-400' };
  return { label: 'Critical', color: 'text-red-400' };
}

function getScoreColor(score: number): string {
  if (score >= 90) return '#22C55E';
  if (score >= 75) return '#10B981';
  if (score >= 60) return '#EAB308';
  if (score >= 40) return '#F97316';
  return '#EF4444';
}

export function PostureScoreCard({ score, previousScore, maxScore = 100 }: PostureScoreCardProps) {
  const grade = getGrade(score);
  const scoreColor = getScoreColor(score);
  const delta = previousScore ? score - previousScore : 0;
  const deltaPercent = previousScore ? ((delta / previousScore) * 100).toFixed(1) : '0';
  const isPositive = delta >= 0;

  // Calculate gradient stops for the progress bar
  const gradientStops = [
    { color: '#EF4444', position: 0 },
    { color: '#F97316', position: 25 },
    { color: '#EAB308', position: 50 },
    { color: '#10B981', position: 75 },
    { color: '#22C55E', position: 100 },
  ];

  return (
    <div className="bg-[#121826] rounded-xl p-6 border border-[#1E293B] glow-accent transition-glow">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-amber-500/10 flex items-center justify-center">
            <Shield className="w-5 h-5 text-amber-500" />
          </div>
          <div>
            <h3 className="text-sm font-medium text-slate-400">Cloud Posture Score</h3>
            <p className="text-xs text-slate-500">Based on {maxScore} security checks</p>
          </div>
        </div>
        
        {/* Trend indicator */}
        <div className={`flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${
          isPositive ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'
        }`}>
          {isPositive ? (
            <TrendingUp className="w-3 h-3" />
          ) : (
            <TrendingDown className="w-3 h-3" />
          )}
          <span>{isPositive ? '+' : ''}{deltaPercent}%</span>
        </div>
      </div>

      {/* Score Display */}
      <div className="flex items-end gap-2 mb-6">
        <span 
          className="text-6xl font-bold tabular-nums tracking-tight"
          style={{ color: scoreColor }}
        >
          {score}
        </span>
        <span className="text-2xl font-medium text-slate-500 mb-2">/ {maxScore}</span>
      </div>

      {/* Grade Bar */}
      <div className="mb-4">
        <div className="h-3 rounded-full overflow-hidden relative"
          style={{
            background: `linear-gradient(to right, ${gradientStops.map(s => `${s.color} ${s.position}%`).join(', ')})`
          }}
        >
          {/* Score indicator */}
          <div 
            className="absolute top-0 bottom-0 w-1 bg-white shadow-lg transform -translate-x-1/2 transition-all duration-500"
            style={{ left: `${score}%` }}
          />
        </div>
        
        {/* Labels */}
        <div className="flex justify-between mt-2 text-xs text-slate-500">
          <span>Critical</span>
          <span>Poor</span>
          <span>Fair</span>
          <span>Good</span>
          <span>Excellent</span>
        </div>
      </div>

      {/* Grade Label */}
      <div className="flex items-center justify-between pt-4 border-t border-[#1E293B]">
        <span className="text-sm text-slate-400">Current Grade</span>
        <span className={`text-lg font-semibold ${grade.color}`}>{grade.label}</span>
      </div>
    </div>
  );
}
