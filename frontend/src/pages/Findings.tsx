import React, { useState, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { 
  AlertOctagon, AlertTriangle, AlertCircle, Info, X,
  Filter, Search, CheckCircle2,
  FileCode, Sparkles, RefreshCw
} from 'lucide-react';
import type { Finding, Severity, FindingStatus } from '../types';
import { useApp } from '../context/AppContext';
import * as api from '../api/client';
import { findings as findingsStrings, empty, common } from '../constants/strings';
import { SEVERITY_STYLES, STATUS_STYLES, TW_COLORS } from '../constants/theme';

const severityIcons: Record<Severity, typeof AlertOctagon> = {
  critical: AlertOctagon,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Info,
  info: Info,
};

interface FilterState {
  severity: Severity[];
  service: string[];
  status: FindingStatus[];
  hasDetection: boolean | null;
}

function FindingDetailPanel({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const Icon = severityIcons[finding.severity];
  const colors = SEVERITY_STYLES[finding.severity];

  return (
    <div className={`fixed inset-y-0 right-0 w-[500px] ${TW_COLORS.bgSurface} border-l ${TW_COLORS.borderDefault} shadow-2xl z-50 flex flex-col`}>
      {/* Header */}
      <div className={`flex items-center justify-between p-5 border-b ${TW_COLORS.borderDefault}`}>
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${colors.bg}`}>
            <Icon className={`w-5 h-5 ${colors.text}`} />
          </div>
          <span className={`text-sm font-medium capitalize ${colors.text}`}>{finding.severity}</span>
        </div>
        <button 
          onClick={onClose}
          className={`p-2 hover:${TW_COLORS.bgElevated} rounded-lg transition-colors`}
        >
          <X className={`w-5 h-5 ${TW_COLORS.textMuted}`} />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-5 space-y-6">
        {/* Title & Resource */}
        <div>
          <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-2`}>{finding.issue}</h2>
          <div className="flex flex-wrap gap-2">
            <span className={`px-2 py-1 ${TW_COLORS.bgElevated} rounded text-xs ${TW_COLORS.textMuted}`}>{finding.service}</span>
            <span className={`px-2 py-1 ${TW_COLORS.bgElevated} rounded text-xs ${TW_COLORS.textMuted}`}>{finding.resource_type}</span>
            <span className={`px-2 py-1 ${TW_COLORS.bgElevated} rounded text-xs ${TW_COLORS.textAccent} font-mono`}>{finding.resource_id}</span>
          </div>
        </div>

        {/* AI Explanation */}
        {finding.ai_explanation && (
          <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-3">
              <Sparkles className={`w-4 h-4 ${TW_COLORS.textAccent}`} />
              <span className={`text-xs font-medium ${TW_COLORS.textAccent}`}>{findingsStrings.detail.aiExplanation}</span>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">{finding.ai_explanation}</p>
          </div>
        )}

        {/* Remediation */}
        {finding.remediation && (
          <div>
            <h3 className={`text-sm font-medium ${TW_COLORS.textMuted} mb-2`}>{findingsStrings.detail.recommendedActions}</h3>
            <p className="text-sm text-slate-300 leading-relaxed">{finding.remediation}</p>
          </div>
        )}

        {/* Evidence */}
        <div>
          <h3 className={`text-sm font-medium ${TW_COLORS.textMuted} mb-2`}>{findingsStrings.detail.evidence}</h3>
          <pre className={`${TW_COLORS.bgElevated} rounded-lg p-4 text-xs text-slate-300 overflow-x-auto`}>
            {JSON.stringify(finding.evidence, null, 2)}
          </pre>
        </div>

        {/* Detection Coverage */}
        <div>
          <h3 className={`text-sm font-medium ${TW_COLORS.textMuted} mb-3`}>{findingsStrings.detail.detectionCoverage}</h3>
          <div className="space-y-2">
            <div className={`flex items-center justify-between p-3 rounded-lg ${finding.has_detection ? 'bg-green-500/5 border border-green-500/20' : TW_COLORS.bgElevated}`}>
              <div className="flex items-center gap-2">
                <FileCode className={`w-4 h-4 ${finding.has_detection ? 'text-green-400' : TW_COLORS.textDisabled}`} />
                <span className="text-sm text-slate-300">{findingsStrings.detail.sigmaRule}</span>
              </div>
              {finding.has_detection ? (
                <span className="text-xs text-green-400">{common.available}</span>
              ) : (
                <span className={`text-xs ${TW_COLORS.textDisabled}`}>{common.notAvailable}</span>
              )}
            </div>
          </div>
        </div>

        {/* Metadata */}
        <div className={`grid grid-cols-2 gap-4 pt-4 border-t ${TW_COLORS.borderDefault}`}>
          <div>
            <span className={`text-xs ${TW_COLORS.textDisabled}`}>{findingsStrings.detail.firstSeen}</span>
            <p className="text-sm text-slate-300 mt-1">
              {finding.first_seen ? new Date(finding.first_seen).toLocaleDateString() : 'N/A'}
            </p>
          </div>
          <div>
            <span className={`text-xs ${TW_COLORS.textDisabled}`}>{common.region}</span>
            <p className="text-sm text-slate-300 mt-1">{finding.region || 'Global'}</p>
          </div>
          <div>
            <span className={`text-xs ${TW_COLORS.textDisabled}`}>{findingsStrings.detail.findingId}</span>
            <p className={`text-xs ${TW_COLORS.textMuted} font-mono mt-1 truncate`}>{finding.finding_id}</p>
          </div>
          <div>
            <span className={`text-xs ${TW_COLORS.textDisabled}`}>{common.status}</span>
            <span className={`inline-block mt-1 px-2 py-0.5 rounded text-xs capitalize ${STATUS_STYLES[finding.finding_status || 'open'].bg} ${STATUS_STYLES[finding.finding_status || 'open'].text}`}>
              {finding.finding_status || 'open'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

export function Findings() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { selectedRunId, serverConnected, runs, searchQuery, setSearchQuery } = useApp();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState<FilterState>({
    severity: [],
    service: [],
    status: [],
    hasDetection: null,
  });

  useEffect(() => {
    if (!selectedRunId || !serverConnected) {
      setFindings([]);
      return;
    }

    const fetchFindings = async () => {
      setLoading(true);
      try {
        const data = await api.getScanResult(selectedRunId) as { findings: Finding[]; scan_date?: string };
        const run = runs.find(r => r.id === selectedRunId);
        const scanTimestamp = data.scan_date || run?.created || new Date().toISOString();
        // Add defaults only when missing; use actual scan time, not "now"
        const processedFindings = (data.findings || []).map(f => ({
          ...f,
          finding_status: f.finding_status || 'open' as FindingStatus,
          first_seen: f.first_seen || scanTimestamp
        }));
        setFindings(processedFindings);
      } catch (err) {
        console.error('Failed to load findings:', err);
        setFindings([]);
      } finally {
        setLoading(false);
      }
    };

    fetchFindings();
  }, [selectedRunId, serverConnected]);

  // Sync filters from URL (severity, service) on mount/URL change
  useEffect(() => {
    const severityParam = searchParams.get('severity');
    const serviceParam = searchParams.get('service');

    if (severityParam) {
      const sevs = severityParam.split(',').filter(Boolean) as Severity[];
      if (sevs.length > 0) {
        setFilters(prev => ({ ...prev, severity: sevs }));
      }
    }
    if (serviceParam) {
      const svcs = serviceParam.split(',').filter(Boolean);
      if (svcs.length > 0) {
        setFilters(prev => ({ ...prev, service: svcs }));
      }
    }
  }, [searchParams]);

  // Open finding by id when findings load (e.g. from /findings?id=xyz)
  useEffect(() => {
    const idParam = searchParams.get('id');
    if (idParam && findings.length > 0) {
      const match = findings.find(f => f.finding_id === idParam);
      if (match) setSelectedFinding(match);
    }
  }, [findings, searchParams]);

  const services = useMemo(() => 
    [...new Set(findings.map(f => f.service))],
    [findings]
  );

  const filteredFindings = useMemo(() => {
    return findings.filter(finding => {
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const matchesSearch = 
          finding.issue.toLowerCase().includes(query) ||
          finding.resource_id.toLowerCase().includes(query) ||
          finding.service.toLowerCase().includes(query);
        if (!matchesSearch) return false;
      }

      if (filters.severity.length > 0 && !filters.severity.includes(finding.severity)) {
        return false;
      }

      if (filters.service.length > 0 && !filters.service.includes(finding.service)) {
        return false;
      }

      if (filters.status.length > 0 && !filters.status.includes(finding.finding_status || 'open')) {
        return false;
      }

      if (filters.hasDetection !== null && finding.has_detection !== filters.hasDetection) {
        return false;
      }

      return true;
    });
  }, [findings, searchQuery, filters]);

  const toggleSeverityFilter = (severity: Severity) => {
    setFilters(prev => ({
      ...prev,
      severity: prev.severity.includes(severity)
        ? prev.severity.filter(s => s !== severity)
        : [...prev.severity, severity]
    }));
  };

  const toggleServiceFilter = (service: string) => {
    setFilters(prev => ({
      ...prev,
      service: prev.service.includes(service)
        ? prev.service.filter(s => s !== service)
        : [...prev.service, service]
    }));
  };

  const toggleStatusFilter = (status: FindingStatus) => {
    setFilters(prev => ({
      ...prev,
      status: prev.status.includes(status)
        ? prev.status.filter(s => s !== status)
        : [...prev.status, status]
    }));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className={`w-6 h-6 ${TW_COLORS.textAccent} animate-spin`} />
      </div>
    );
  }

  if (!serverConnected || !selectedRunId) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="w-12 h-12 text-yellow-400 mx-auto mb-4" />
        <h2 className={`text-xl font-semibold ${TW_COLORS.textSecondary} mb-2`}>
          {!serverConnected ? empty.serverNotConnected : empty.noRunSelected}
        </h2>
        <p className={TW_COLORS.textDisabled}>
          {!serverConnected 
            ? empty.startServerHint
            : findingsStrings.selectRunHint}
        </p>
      </div>
    );
  }

  return (
    <div className="flex gap-6">
      {/* Filters Sidebar */}
      <div className={`w-64 shrink-0 ${showFilters ? 'block' : 'hidden lg:block'}`}>
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-4 sticky top-6`}>
          <h3 className={`text-sm font-medium ${TW_COLORS.textSecondary} mb-4`}>{findingsStrings.filtersTitle}</h3>

          {/* Severity */}
          <div className="mb-6">
            <h4 className={`text-xs font-medium ${TW_COLORS.textMuted} mb-2`}>{findingsStrings.severityFilter}</h4>
            <div className="space-y-1">
              {(['critical', 'high', 'medium', 'low'] as Severity[]).map(severity => (
                <button
                  key={severity}
                  onClick={() => toggleSeverityFilter(severity)}
                  className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    filters.severity.includes(severity)
                      ? `${SEVERITY_STYLES[severity].bg} ${SEVERITY_STYLES[severity].text}`
                      : `${TW_COLORS.textMuted} hover:bg-[#1a2233]`
                  }`}
                >
                  {React.createElement(severityIcons[severity], { className: 'w-4 h-4' })}
                  <span className="capitalize">{severity}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Service */}
          {services.length > 0 && (
            <div className="mb-6">
              <h4 className={`text-xs font-medium ${TW_COLORS.textMuted} mb-2`}>{findingsStrings.serviceFilter}</h4>
              <div className="space-y-1">
                {services.map(service => (
                  <button
                    key={service}
                    onClick={() => toggleServiceFilter(service)}
                    className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                      filters.service.includes(service)
                        ? `${TW_COLORS.bgAccent} ${TW_COLORS.textAccent}`
                        : `${TW_COLORS.textMuted} hover:bg-[#1a2233]`
                    }`}
                  >
                    <span>{service}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Status */}
          <div className="mb-6">
            <h4 className={`text-xs font-medium ${TW_COLORS.textMuted} mb-2`}>{findingsStrings.statusFilter}</h4>
            <div className="space-y-1">
              {(['open', 'resolved', 'suppressed'] as FindingStatus[]).map(status => (
                <button
                  key={status}
                  onClick={() => toggleStatusFilter(status)}
                  className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    filters.status.includes(status)
                      ? `${STATUS_STYLES[status].bg} ${STATUS_STYLES[status].text}`
                      : `${TW_COLORS.textMuted} hover:bg-[#1a2233]`
                  }`}
                >
                  <span className="capitalize">{status}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Has Detection */}
          <div>
            <h4 className={`text-xs font-medium ${TW_COLORS.textMuted} mb-2`}>{findingsStrings.detectionFilter}</h4>
            <div className="space-y-1">
              <button
                onClick={() => setFilters(prev => ({ ...prev, hasDetection: prev.hasDetection === true ? null : true }))}
                className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                  filters.hasDetection === true
                    ? 'bg-green-500/10 text-green-400'
                    : `${TW_COLORS.textMuted} hover:bg-[#1a2233]`
                }`}
              >
                <CheckCircle2 className="w-4 h-4" />
                <span>{findingsStrings.hasDetection}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 min-w-0">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>{findingsStrings.title}</h1>
            <p className={`text-sm ${TW_COLORS.textDisabled} mt-1`}>
              {findingsStrings.countLabel(filteredFindings.length, findings.length)}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button 
              onClick={() => setShowFilters(!showFilters)}
              className={`lg:hidden p-2 rounded-lg ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault}`}
            >
              <Filter className={`w-5 h-5 ${TW_COLORS.textMuted}`} />
            </button>
          </div>
        </div>

        {/* Search */}
        <div className="mb-6">
          <div className="relative">
            <Search className={`absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 ${TW_COLORS.textDisabled}`} />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={findingsStrings.searchPlaceholder}
              className={`w-full pl-10 pr-4 py-2.5 ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} placeholder:${TW_COLORS.textDisabled} focus:outline-none focus:border-amber-500/50 transition-colors`}
            />
          </div>
        </div>

        {/* Table */}
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} overflow-hidden`}>
          <table className="w-full">
            <thead>
              <tr className={`border-b ${TW_COLORS.borderDefault}`}>
                <th className={`px-5 py-3 text-left text-xs font-medium ${TW_COLORS.textMuted} uppercase tracking-wider`}>{common.severity}</th>
                <th className={`px-5 py-3 text-left text-xs font-medium ${TW_COLORS.textMuted} uppercase tracking-wider`}>Finding</th>
                <th className={`px-5 py-3 text-left text-xs font-medium ${TW_COLORS.textMuted} uppercase tracking-wider`}>{common.resource}</th>
                <th className={`px-5 py-3 text-left text-xs font-medium ${TW_COLORS.textMuted} uppercase tracking-wider`}>{common.service}</th>
                <th className={`px-5 py-3 text-left text-xs font-medium ${TW_COLORS.textMuted} uppercase tracking-wider`}>{common.region}</th>
              </tr>
            </thead>
            <tbody className={`divide-y divide-[#1E293B]`}>
              {filteredFindings.map((finding, index) => {
                const Icon = severityIcons[finding.severity];
                const colors = SEVERITY_STYLES[finding.severity];
                
                return (
                  <tr 
                    key={finding.finding_id || index}
                    onClick={() => setSelectedFinding(finding)}
                    className="hover:bg-[#1a2233] cursor-pointer transition-colors"
                  >
                    <td className="px-5 py-4">
                      <div className={`inline-flex items-center gap-2 px-2.5 py-1 rounded-full ${colors.bg}`}>
                        <Icon className={`w-3.5 h-3.5 ${colors.text}`} />
                        <span className={`text-xs font-medium capitalize ${colors.text}`}>{finding.severity}</span>
                      </div>
                    </td>
                    <td className="px-5 py-4">
                      <p className={`text-sm ${TW_COLORS.textSecondary} line-clamp-1`}>{finding.issue}</p>
                    </td>
                    <td className="px-5 py-4">
                      <code className={`text-xs ${TW_COLORS.textMuted} font-mono`}>{finding.resource_id}</code>
                    </td>
                    <td className="px-5 py-4">
                      <span className={`text-sm ${TW_COLORS.textMuted}`}>{finding.service}</span>
                    </td>
                    <td className="px-5 py-4">
                      <span className={`text-sm ${TW_COLORS.textMuted}`}>{finding.region || 'Global'}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {filteredFindings.length === 0 && (
            <div className="p-12 text-center">
              <p className={TW_COLORS.textDisabled}>
                {findings.length === 0 ? findingsStrings.noFindings : findingsStrings.noMatchingFindings}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Detail Panel */}
      {selectedFinding && (
        <>
          <div 
            className="fixed inset-0 bg-black/50 z-40"
            onClick={() => setSelectedFinding(null)}
          />
          <FindingDetailPanel 
            finding={selectedFinding} 
            onClose={() => setSelectedFinding(null)} 
          />
        </>
      )}
    </div>
  );
}
