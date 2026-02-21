import { useNavigate } from 'react-router-dom';
import { Shield, CheckCircle2, XCircle, ChevronDown, ChevronRight, RefreshCw, AlertTriangle, ClipboardList, ExternalLink } from 'lucide-react';
import { useApp } from '../context/AppContext';
import * as api from '../api/client';
import type { Finding, ComplianceFramework } from '../types';
import { useState, useEffect, useMemo } from 'react';
import { COMPLIANCE_FRAMEWORK_CONTROLS } from '../constants/complianceMappings';
import { calculateComplianceWithControls, type FrameworkWithControls } from '../utils/compliance';
import { compliance as complianceStrings, empty } from '../constants/strings';
import { TW_COLORS } from '../constants/theme';

/** Expandable framework list for empty state - shows controls when expanded */
function EmptyStateFrameworkList() {
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <div className="space-y-3 text-left">
      {COMPLIANCE_FRAMEWORK_CONTROLS.map((framework) => {
        const isExpanded = expanded === framework.short_name;
        return (
          <div
            key={framework.short_name}
            className={`${TW_COLORS.bgSurface} rounded-lg border ${TW_COLORS.borderDefault} overflow-hidden`}
          >
            <div
              role="button"
              tabIndex={0}
              onClick={() => setExpanded(isExpanded ? null : framework.short_name)}
              onKeyDown={(e) => e.key === 'Enter' && setExpanded(isExpanded ? null : framework.short_name)}
              className="flex items-center gap-3 p-3 cursor-pointer hover:bg-[#1a2233] transition-colors"
            >
              <Shield className={`w-5 h-5 ${TW_COLORS.textAccent} shrink-0`} />
              <div className="flex-1 min-w-0">
                <p className={`text-sm font-medium ${TW_COLORS.textSecondary}`}>{framework.short_name}</p>
                <p className={`text-xs ${TW_COLORS.textDisabled}`}>{framework.controls.length} controls assessed</p>
              </div>
              {isExpanded ? (
                <ChevronDown className={`w-5 h-5 ${TW_COLORS.textDisabled} shrink-0`} />
              ) : (
                <ChevronRight className={`w-5 h-5 ${TW_COLORS.textDisabled} shrink-0`} />
              )}
            </div>
            {isExpanded && (
              <div className={`border-t ${TW_COLORS.borderDefault} p-3 max-h-60 overflow-y-auto`}>
                <p className={`text-xs font-medium ${TW_COLORS.textMuted} mb-2`}>Controls assessed:</p>
                <div className="space-y-2">
                  {framework.controls.map((control) => (
                    <div
                      key={control.id}
                      className={`flex items-start gap-2 text-xs ${TW_COLORS.textDisabled}`}
                    >
                      <span className={`font-mono ${TW_COLORS.textMuted} shrink-0`}>{control.id}</span>
                      <span>{control.name}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export function Compliance() {
  const navigate = useNavigate();
  const { selectedRunId, serverConnected } = useApp();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!selectedRunId || !serverConnected) {
      setFindings([]);
      return;
    }

    const fetchFindings = async () => {
      setLoading(true);
      try {
        const data = await api.getScanResult(selectedRunId) as { findings: Finding[] };
        setFindings(data.findings || []);
      } catch (err) {
        console.error('Failed to load findings:', err);
        setFindings([]);
      } finally {
        setLoading(false);
      }
    };

    fetchFindings();
  }, [selectedRunId, serverConnected]);

  const frameworks = useMemo(() => (
    findings.length > 0 ? calculateComplianceWithControls(findings) : null
  ), [findings]);
  const hasData = frameworks !== null;
  const [expandedFramework, setExpandedFramework] = useState<string | null>(null);

  const totalControls = COMPLIANCE_FRAMEWORK_CONTROLS.reduce((sum, f) => sum + f.controls.length, 0);
  const passedControls = hasData ? frameworks.reduce((sum, f) => sum + f.passed_controls, 0) : 0;
  const overallPercentage = hasData && totalControls > 0 ? Math.round((passedControls / totalControls) * 100) : 0;

  if (!serverConnected) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="w-12 h-12 text-yellow-400 mx-auto mb-4" />
        <h2 className={`text-xl font-semibold ${TW_COLORS.textSecondary} mb-2`}>{empty.serverNotConnected}</h2>
        <p className={TW_COLORS.textDisabled}>{empty.startServerHint}</p>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className={`w-6 h-6 ${TW_COLORS.textAccent} animate-spin`} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>{complianceStrings.title}</h1>
          <p className={`text-sm ${TW_COLORS.textDisabled} mt-1`}>
            {complianceStrings.subtitle}
          </p>
        </div>
      </div>

      {/* Empty State - No scan data (frameworks still expandable to show controls) */}
      {!hasData && (
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-12`}>
          <div className="text-center max-w-2xl mx-auto">
            <div className={`w-16 h-16 rounded-full ${TW_COLORS.bgSurface} flex items-center justify-center mx-auto mb-6`}>
              <ClipboardList className={`w-8 h-8 ${TW_COLORS.textDisabled}`} />
            </div>
            <h2 className={`text-xl font-semibold ${TW_COLORS.textSecondary} mb-2`}>No Compliance Data</h2>
            <p className={`${TW_COLORS.textDisabled} mb-6`}>
              Run a security scan to calculate compliance against these frameworks. Click a framework to see which controls are assessed:
            </p>
            <EmptyStateFrameworkList />
            <p className={`text-sm ${TW_COLORS.textDisabled} mt-6`}>
              Total: {totalControls} controls across {COMPLIANCE_FRAMEWORK_CONTROLS.length} frameworks
            </p>
          </div>
        </div>
      )}

      {/* Overall Summary - Only show when we have data */}
      {hasData && (
        <>
          <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary}`}>{complianceStrings.overallCompliance}</h2>
                <p className={`text-sm ${TW_COLORS.textDisabled}`}>{complianceStrings.acrossAllFrameworks}</p>
              </div>
              <div className="text-right">
                <p className={`text-4xl font-bold ${overallPercentage >= 75 ? 'text-green-400' : overallPercentage >= 50 ? 'text-yellow-400' : 'text-red-400'}`}>
                  {overallPercentage}%
                </p>
                <p className={`text-sm ${TW_COLORS.textDisabled}`}>{complianceStrings.controlsLabel(passedControls, totalControls)}</p>
              </div>
            </div>

            <div className={`h-3 ${TW_COLORS.bgSurface} rounded-full overflow-hidden`}>
              <div 
                className={`h-full rounded-full transition-all ${
                  overallPercentage >= 75 ? 'bg-green-500' : 
                  overallPercentage >= 50 ? 'bg-yellow-500' : 'bg-red-500'
                }`}
                style={{ width: `${overallPercentage}%` }}
              />
            </div>
          </div>

          {/* Frameworks */}
          <div className="space-y-4">
            {frameworks.map((fw) => {
              const isExpanded = expandedFramework === fw.short_name;
              return (
                <div
                  key={fw.short_name}
                  className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} overflow-hidden ${TW_COLORS.borderHover} transition-all`}
                >
                  <div
                    role="button"
                    tabIndex={0}
                    onClick={() => setExpandedFramework(isExpanded ? null : fw.short_name)}
                    onKeyDown={(e) => e.key === 'Enter' && setExpandedFramework(isExpanded ? null : fw.short_name)}
                    className="p-6 cursor-pointer group"
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center gap-4">
                        <div className={`w-12 h-12 rounded-lg ${TW_COLORS.bgAccent} flex items-center justify-center`}>
                          <Shield className={`w-6 h-6 ${TW_COLORS.textAccent}`} />
                        </div>
                        <div>
                          <h3 className={`text-lg font-semibold ${TW_COLORS.textSecondary}`}>{fw.short_name}</h3>
                          <p className={`text-sm ${TW_COLORS.textDisabled}`}>{fw.name}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right">
                          <p className={`text-2xl font-bold ${
                            fw.percentage >= 75 ? 'text-green-400' :
                            fw.percentage >= 50 ? 'text-yellow-400' : 'text-red-400'
                          }`}>
                            {fw.percentage}%
                          </p>
                        </div>
                        {isExpanded ? (
                          <ChevronDown className={`w-5 h-5 ${TW_COLORS.textDisabled}`} />
                        ) : (
                          <ChevronRight className={`w-5 h-5 ${TW_COLORS.textDisabled} opacity-0 group-hover:opacity-100 transition-opacity`} />
                        )}
                      </div>
                    </div>

                    <div className="mb-4">
                      <div className={`h-2 ${TW_COLORS.bgSurface} rounded-full overflow-hidden`}>
                        <div
                          className={`h-full rounded-full transition-all ${
                            fw.percentage >= 75 ? 'bg-green-500' :
                            fw.percentage >= 50 ? 'bg-yellow-500' : 'bg-red-500'
                          }`}
                          style={{ width: `${fw.percentage}%` }}
                        />
                      </div>
                    </div>

                    <div className="flex items-center gap-6">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-green-400" />
                        <span className="text-sm text-slate-300">{fw.passed_controls} {complianceStrings.passed}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <XCircle className="w-4 h-4 text-red-400" />
                        <span className="text-sm text-slate-300">{fw.failed_controls} {complianceStrings.failed}</span>
                      </div>
                      <span className={`text-sm ${TW_COLORS.textDisabled}`}>
                        {fw.total_controls} {complianceStrings.totalControls}
                      </span>
                      <span className={`text-xs ${TW_COLORS.textDisabled}`}>
                        {isExpanded ? 'Click to collapse' : 'Click to view controls'}
                      </span>
                    </div>
                  </div>

                  {/* Expanded: list of controls assessed */}
                  {isExpanded && fw.controlResults && (
                    <div className={`border-t ${TW_COLORS.borderDefault} ${TW_COLORS.bgSurface} p-4`}>
                      <h4 className={`text-sm font-medium ${TW_COLORS.textSecondary} mb-3`}>Controls assessed</h4>
                      <div className="space-y-2 max-h-80 overflow-y-auto">
                        {fw.controlResults.map(({ control, passed, violatingFindings }) => (
                          <div
                            key={control.id}
                            className={`flex items-start gap-3 p-3 rounded-lg ${
                              passed ? 'bg-green-500/5 border border-green-500/20' : 'bg-red-500/5 border border-red-500/20'
                            }`}
                          >
                            {passed ? (
                              <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0 mt-0.5" />
                            ) : (
                              <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                            )}
                            <div className="flex-1 min-w-0">
                              <p className={`text-sm font-medium ${TW_COLORS.textSecondary}`}>
                                <span className={`${TW_COLORS.textMuted} font-mono`}>{control.id}</span> {control.name}
                              </p>
                              {violatingFindings.length > 0 && (
                                <div className="mt-2 space-y-1">
                                  <p className={`text-xs ${TW_COLORS.textDisabled}`}>Violations:</p>
                                  {violatingFindings.slice(0, 5).map((f) => (
                                    <button
                                      key={f.finding_id || `${f.service}-${f.resource_id}-${f.issue}`}
                                      type="button"
                                      onClick={(e) => { e.stopPropagation(); navigate(`/findings?id=${encodeURIComponent(f.finding_id || '')}`); }}
                                      className={`block text-left text-xs ${TW_COLORS.textAccent} hover:text-amber-300 transition-colors flex items-center gap-1`}
                                    >
                                      <ExternalLink className="w-3 h-3" />
                                      {f.issue} — {f.resource_id}
                                    </button>
                                  ))}
                                  {violatingFindings.length > 5 && (
                                    <p className={`text-xs ${TW_COLORS.textDisabled}`}>+{violatingFindings.length - 5} more</p>
                                  )}
                                </div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                      <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); navigate('/findings'); }}
                        className={`mt-4 text-sm ${TW_COLORS.textAccent} hover:text-amber-300 transition-colors flex items-center gap-2`}
                      >
                        <ExternalLink className="w-4 h-4" />
                        View all findings
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Note */}
          <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-4">
            <p className="text-sm text-amber-400/80">
              <strong>Note:</strong> {complianceStrings.disclaimer}
            </p>
          </div>
        </>
      )}
    </div>
  );
}
