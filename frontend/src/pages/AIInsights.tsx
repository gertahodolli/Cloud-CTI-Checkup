import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Sparkles, AlertTriangle, User, Clock, Shield, 
  FileCode, Download, AlertOctagon,
  AlertCircle, Info, Server, RefreshCw
} from 'lucide-react';
import type { Severity, CloudTrailAISummary as AISummaryType } from '../types';
import { useApp } from '../context/AppContext';
import * as api from '../api/client';
import { aiInsights, empty } from '../constants/strings';
import { SEVERITY_STYLES, TW_COLORS, CHART_COLORS } from '../constants/theme';

/** Safely format a timestamp - backend uses `time`, frontend type uses `timestamp`. Returns raw string if unparseable. */
function formatTimelineTime(value: string | undefined): string {
  const ts = value?.trim();
  if (!ts || ts === 'unknown') return '—';
  const d = new Date(ts);
  return isNaN(d.getTime()) ? ts : d.toLocaleString();
}

const severityIcons: Record<Severity, typeof AlertOctagon> = {
  critical: AlertOctagon,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Info,
  info: Info,
};

export function AIInsights() {
  const navigate = useNavigate();
  const { selectedRunId, serverConnected } = useApp();
  const [summary, setSummary] = useState<AISummaryType | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedRunId || !serverConnected) {
      setSummary(null);
      return;
    }

    const fetchSummary = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.getAISummary(selectedRunId) as AISummaryType;
        setSummary(data);
      } catch (err) {
        // AI summary may not exist for all runs
        setError(err instanceof Error ? err.message : 'No AI summary available');
        setSummary(null);
      } finally {
        setLoading(false);
      }
    };

    fetchSummary();
  }, [selectedRunId, serverConnected]);

  // Baseline runs produce a summary file but it's not AI - show specific message
  const isBaselineRun = summary != null && (
    summary.type === 'cloudtrail_baseline_summary' ||
    (summary as { input?: { mode?: string } }).input?.mode === 'baseline'
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className={`w-6 h-6 ${TW_COLORS.textAccent} animate-spin`} />
      </div>
    );
  }

  if (!serverConnected) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="w-12 h-12 text-yellow-400 mx-auto mb-4" />
        <h2 className={`text-xl font-semibold ${TW_COLORS.textSecondary} mb-2`}>{empty.serverNotConnected}</h2>
        <p className={TW_COLORS.textDisabled}>{empty.startServerHint}</p>
      </div>
    );
  }

  if (!summary || isBaselineRun) {
    const isBaseline = !!summary && isBaselineRun;
    return (
      <div className="space-y-6">
        {/* Page Header */}
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-amber-500/20 to-purple-500/20 flex items-center justify-center">
                <Sparkles className={`w-5 h-5 ${TW_COLORS.textAccent}`} />
              </div>
              <h1 className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>{aiInsights.title}</h1>
            </div>
            <p className={`text-sm ${TW_COLORS.textDisabled}`}>{aiInsights.subtitle}</p>
          </div>
        </div>

        <div className={`text-center py-12 ${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault}`}>
          <Sparkles className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <h2 className={`text-xl font-semibold ${TW_COLORS.textSecondary} mb-2`}>
            {isBaseline ? aiInsights.baselineRun : aiInsights.noSummary}
          </h2>
          <p className={`${TW_COLORS.textDisabled} mb-6 max-w-md mx-auto`}>
            {!selectedRunId 
              ? aiInsights.selectRunHint
              : isBaseline
                ? aiInsights.baselineRunHint
                : aiInsights.noSummaryHint}
          </p>
          {selectedRunId && !isBaseline && (
            <code className={`text-sm ${TW_COLORS.textMuted} bg-slate-800 px-4 py-2 rounded-lg`}>
              {aiInsights.cliCommand}
            </code>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-amber-500/20 to-purple-500/20 flex items-center justify-center">
              <Sparkles className={`w-5 h-5 ${TW_COLORS.textAccent}`} />
            </div>
            <h1 className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>{aiInsights.title}</h1>
          </div>
          <p className={`text-sm ${TW_COLORS.textDisabled}`}>{aiInsights.subtitle}</p>
        </div>
      </div>

      {/* Incident Overview */}
      <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
        <div className="flex items-start justify-between mb-4">
          <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary}`}>{aiInsights.incidentOverview}</h2>
          <div className="flex items-center gap-2">
            <span className={`text-xs ${TW_COLORS.textDisabled}`}>{aiInsights.confidence}</span>
            <div className="flex items-center gap-2">
              <div className={`w-24 h-2 ${TW_COLORS.bgSurface} rounded-full overflow-hidden`}>
                <div 
                  className="h-full bg-gradient-to-r from-amber-500 to-green-500 rounded-full"
                  style={{ width: `${summary.confidence}%` }}
                />
              </div>
              <span className={`text-sm font-medium ${TW_COLORS.textAccent}`}>{summary.confidence}%</span>
            </div>
          </div>
        </div>

        <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-4 mb-6">
          <div className="flex items-start gap-3">
            <Sparkles className={`w-5 h-5 ${TW_COLORS.textAccent} shrink-0 mt-0.5`} />
            <div>
              <p className={`text-sm ${TW_COLORS.textAccent}/80 mb-2 text-xs font-medium`}>
                AI-assisted summary (based on evidence)
              </p>
              <p className="text-sm text-slate-300 leading-relaxed">{summary.summary_text}</p>
            </div>
          </div>
        </div>

        {/* Limitations */}
        {summary.limitations && summary.limitations.length > 0 && (
          <div className={`${TW_COLORS.bgSurface} rounded-lg p-4`}>
            <h4 className={`text-xs font-medium ${TW_COLORS.textMuted} mb-2`}>{aiInsights.analysisLimitations}</h4>
            <ul className="space-y-1">
              {summary.limitations.map((limitation, index) => (
                <li key={index} className={`text-xs ${TW_COLORS.textDisabled} flex items-start gap-2`}>
                  <span className="text-slate-600">•</span>
                  {limitation}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-12 gap-6">
        {/* Timeline */}
        <div className="col-span-7">
          <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
            <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-6`}>{aiInsights.eventTimeline}</h2>
            
            {summary.timeline && summary.timeline.length > 0 ? (
              <div className="relative">
                <div className={`absolute left-[18px] top-0 bottom-0 w-px ${TW_COLORS.bgSurface}`} />
                
                <div className="space-y-6">
                  {summary.timeline.map((event, index) => {
                    const colors = event.severity ? SEVERITY_STYLES[event.severity] : SEVERITY_STYLES.info;
                    const Icon = event.severity ? severityIcons[event.severity] : Clock;
                    
                    return (
                      <div key={index} className="relative flex gap-4">
                        <div className={`relative z-10 w-9 h-9 rounded-full ${colors.bg} border-2 ${colors.border} flex items-center justify-center ${TW_COLORS.bgElevated}`}>
                          <Icon className={`w-4 h-4 ${colors.text}`} />
                        </div>
                        
                        <div className="flex-1 pb-6">
                          <div className="flex items-start justify-between">
                            <div>
                              <p className={`text-sm font-medium ${TW_COLORS.textSecondary}`}>{event.event}</p>
                              {event.actor && (
                                <div className="flex items-center gap-1.5 mt-1">
                                  <User className={`w-3 h-3 ${TW_COLORS.textDisabled}`} />
                                  <span className={`text-xs ${TW_COLORS.textMuted}`}>{event.actor}</span>
                                </div>
                              )}
                            </div>
                            <span className={`text-xs ${TW_COLORS.textDisabled}`}>
                              {formatTimelineTime(event.timestamp ?? event.time)}
                            </span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ) : (
              <p className={`${TW_COLORS.textDisabled} text-center py-8`}>{aiInsights.noTimelineEvents}</p>
            )}
          </div>
        </div>

        {/* Right Column */}
        <div className="col-span-5 space-y-6">
          {/* Key Actors */}
          <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
            <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{aiInsights.keyActors}</h2>
            
            {summary.top_actors && summary.top_actors.length > 0 ? (
              <div className="space-y-4">
                {summary.top_actors.map((actor, index) => {
                  const colors = SEVERITY_STYLES[actor.risk_level];
                  
                  return (
                    <div key={index} className={`p-4 rounded-lg border ${colors.border} ${colors.bg}`}>
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <User className={`w-4 h-4 ${colors.text}`} />
                          <span className={`text-sm font-medium ${TW_COLORS.textSecondary}`}>{actor.identity}</span>
                        </div>
                        <span className={`text-xs px-2 py-0.5 rounded ${colors.bg} ${colors.text} capitalize`}>
                          {actor.risk_level}
                        </span>
                      </div>
                      <p className={`text-xs ${TW_COLORS.textDisabled} mb-2`}>{actor.identity_type} • {actor.event_count} events</p>
                      {actor.notable_actions && (
                        <div className="flex flex-wrap gap-1">
                          {actor.notable_actions.map((action, i) => (
                            <span key={i} className={`text-xs px-2 py-0.5 ${TW_COLORS.bgSurface} rounded ${TW_COLORS.textMuted}`}>
                              {action}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className={`${TW_COLORS.textDisabled} text-center py-4`}>{aiInsights.noActorsIdentified}</p>
            )}
          </div>

          {/* Affected Services */}
          {summary.affected_services && summary.affected_services.length > 0 && (
            <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
              <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{aiInsights.affectedServices}</h2>
              <div className="flex flex-wrap gap-2">
                {summary.affected_services.map((service, index) => (
                  <span 
                    key={index}
                    className={`flex items-center gap-2 px-3 py-2 ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-lg text-sm text-slate-300`}
                  >
                    <Server className={`w-4 h-4 ${TW_COLORS.textAccent}`} />
                    {service}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Key Observations */}
      {summary.key_observations && summary.key_observations.length > 0 && (
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
          <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{aiInsights.keyObservations}</h2>
          <div className="grid grid-cols-2 gap-4">
            {summary.key_observations.map((observation, index) => (
              <div key={index} className={`flex items-start gap-3 p-4 ${TW_COLORS.bgSurface} rounded-lg`}>
                <div className={`w-6 h-6 rounded-full ${TW_COLORS.bgAccent} flex items-center justify-center shrink-0`}>
                  <span className={`text-xs font-medium ${TW_COLORS.textAccent}`}>{index + 1}</span>
                </div>
                <p className="text-sm text-slate-300">{observation}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommended Actions */}
      {summary.recommended_actions && summary.recommended_actions.length > 0 && (
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
          <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{aiInsights.recommendedActions}</h2>
          <div className="space-y-3">
            {summary.recommended_actions.map((action, index) => (
              <div key={index} className={`flex items-start gap-3 p-4 ${TW_COLORS.bgSurface} rounded-lg group hover:${TW_COLORS.bgElevated} transition-colors`}>
                <div className="w-6 h-6 rounded bg-green-500/10 flex items-center justify-center shrink-0">
                  <Shield className="w-3.5 h-3.5 text-green-400" />
                </div>
                <p className="text-sm text-slate-300 flex-1">{action}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommended Detections */}
      {summary.recommended_detections && summary.recommended_detections.length > 0 && (
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
          <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{aiInsights.recommendedDetections}</h2>
          
          <div className="grid grid-cols-2 gap-4">
            {summary.recommended_detections.map((detection, index) => (
              <div key={index} className={`p-4 ${TW_COLORS.bgSurface} rounded-lg border ${TW_COLORS.borderDefault} ${TW_COLORS.borderHover} transition-colors`}>
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <FileCode className={`w-4 h-4 ${TW_COLORS.textAccent}`} />
                    <span className={`text-sm font-medium ${TW_COLORS.textSecondary}`}>{detection.name}</span>
                  </div>
                  <span className={`text-xs px-2 py-0.5 ${TW_COLORS.bgElevated} rounded ${TW_COLORS.textMuted} uppercase`}>
                    {detection.type}
                  </span>
                </div>
                <p className={`text-xs ${TW_COLORS.textDisabled} mb-3`}>{detection.description}</p>
                {detection.available && (
                  <button
                    type="button"
                    onClick={() => navigate('/reports')}
                    className={`flex items-center gap-1.5 text-xs ${TW_COLORS.textAccent} hover:text-amber-300 transition-colors`}
                  >
                    <Download className="w-3.5 h-3.5" />
                    Download
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
