import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { CheckCircle2, XCircle, ChevronRight, ChevronDown } from 'lucide-react';
import type { ComplianceFramework } from '../../types';
import type { FrameworkWithControls } from '../../utils/compliance';
import { TW_COLORS } from '../../constants/theme';

interface ComplianceSectionProps {
  frameworks: (ComplianceFramework | FrameworkWithControls)[];
}

function ComplianceCard({ framework, onNavigate }: { framework: ComplianceFramework | FrameworkWithControls; onNavigate: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const hasControls = 'controlResults' in framework && framework.controlResults?.length > 0;

  const getProgressColor = (percentage: number) => {
    if (percentage >= 90) return 'bg-green-500';
    if (percentage >= 75) return 'bg-emerald-500';
    if (percentage >= 60) return 'bg-yellow-500';
    if (percentage >= 40) return 'bg-orange-500';
    return 'bg-red-500';
  };

  const progressColor = getProgressColor(framework.percentage);

  const handleClick = () => {
    if (hasControls) {
      setExpanded((e) => !e);
    } else {
      onNavigate();
    }
  };

  return (
    <div className="bg-[#121826] rounded-xl border border-[#1E293B] hover:border-[#334155] transition-all overflow-hidden">
      <div
        role="button"
        tabIndex={0}
        onClick={handleClick}
        onKeyDown={(e) => e.key === 'Enter' && handleClick()}
        className="p-5 cursor-pointer group"
      >
        <div className="flex items-start justify-between mb-4">
          <div>
            <h4 className="text-sm font-medium text-slate-200 mb-1">{framework.short_name}</h4>
            <p className="text-xs text-slate-500 line-clamp-1">{framework.name}</p>
          </div>
          {hasControls ? (
            expanded ? (
              <ChevronDown className="w-4 h-4 text-slate-500" />
            ) : (
              <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-slate-400 transition-colors" />
            )
          ) : (
            <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-slate-400 transition-colors" />
          )}
        </div>

        {/* Progress bar */}
        <div className="mb-4">
          <div className="h-2 bg-[#1E293B] rounded-full overflow-hidden">
            <div
              className={`h-full ${progressColor} rounded-full transition-all duration-500`}
              style={{ width: `${framework.percentage}%` }}
            />
          </div>
        </div>

        {/* Stats */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-green-400" />
              <span className="text-sm text-slate-300">{framework.passed_controls}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <XCircle className="w-4 h-4 text-red-400" />
              <span className="text-sm text-slate-300">{framework.failed_controls}</span>
            </div>
          </div>
          <span className={`text-lg font-semibold ${
            framework.percentage >= 75 ? 'text-green-400' :
            framework.percentage >= 50 ? 'text-yellow-400' : 'text-red-400'
          }`}>
            {framework.percentage}%
          </span>
        </div>
      </div>

      {/* Expanded: list of controls */}
      {hasControls && expanded && 'controlResults' in framework && (
        <div className={`border-t border-[#1E293B] bg-[#0d1321] p-4 max-h-48 overflow-y-auto`}>
          <p className={`text-xs font-medium ${TW_COLORS.textMuted} mb-2`}>Controls assessed ({framework.controlResults.length})</p>
          <div className="space-y-2">
            {framework.controlResults.map(({ control, passed }) => (
              <div
                key={control.id}
                className={`flex items-center gap-2 text-xs ${
                  passed ? 'text-green-400/90' : 'text-red-400/90'
                }`}
              >
                {passed ? <CheckCircle2 className="w-3.5 h-3.5 shrink-0" /> : <XCircle className="w-3.5 h-3.5 shrink-0" />}
                <span className={`font-mono ${TW_COLORS.textMuted}`}>{control.id}</span>
                <span className={TW_COLORS.textDisabled}>{control.name}</span>
              </div>
            ))}
          </div>
          <button
            type="button"
            onClick={(e) => { e.stopPropagation(); onNavigate(); }}
            className={`mt-3 text-xs ${TW_COLORS.textAccent} hover:text-amber-300 transition-colors`}
          >
            View full details →
          </button>
        </div>
      )}
    </div>
  );
}

export function ComplianceSection({ frameworks }: ComplianceSectionProps) {
  const navigate = useNavigate();

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-slate-200">Compliance Status</h3>
        <button
          type="button"
          onClick={() => navigate('/compliance')}
          className="text-sm text-amber-500 hover:text-amber-400 font-medium transition-colors"
        >
          View All Frameworks
        </button>
      </div>
      
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {frameworks.map((framework) => (
          <ComplianceCard
            key={framework.short_name}
            framework={framework}
            onNavigate={() => navigate('/compliance')}
          />
        ))}
      </div>
    </div>
  );
}
