import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, AlertTriangle, AlertOctagon, Clock, RefreshCw } from 'lucide-react';
import { useApp } from '../context/AppContext';
import * as api from '../api/client';
import type { Finding, Severity } from '../types';
import { alerts as alertsStrings, empty, time } from '../constants/strings';
import { SEVERITY_STYLES, TW_COLORS } from '../constants/theme';

/** Deterministic fallback when finding_id is missing (e.g. legacy scan data). */
function fallbackFindingId(f: Finding): string {
  const parts = [f.service, f.resource_type || 'resource', f.resource_id, f.issue].map(s => String(s || '').replace(/[|\s]/g, '_'));
  return `legacy-${parts.join('|')}`;
}

// Generate alerts from findings (critical and high severity)
function generateAlertsFromFindings(findings: Finding[]): Array<{
  id: string;
  title: string;
  description: string;
  severity: Severity;
  time: string;
  finding: Finding;
}> {
  return findings
    .filter(f => f.severity === 'critical' || f.severity === 'high')
    .map(f => ({
      id: f.finding_id || fallbackFindingId(f),
      title: f.severity === 'critical' ? alertsStrings.criticalFinding : alertsStrings.highFinding,
      description: f.issue,
      severity: f.severity,
      time: f.first_seen || new Date().toISOString(),
      finding: f
    }))
    .sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime());
}

export function Alerts() {
  const navigate = useNavigate();
  const { selectedRunId, serverConnected } = useApp();
  const [alerts, setAlerts] = useState<ReturnType<typeof generateAlertsFromFindings>>([]);
  const [loading, setLoading] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState<Severity | null>(null);

  useEffect(() => {
    if (!selectedRunId || !serverConnected) {
      setAlerts([]);
      return;
    }

    const fetchAlerts = async () => {
      setLoading(true);
      try {
        const data = await api.getScanResult(selectedRunId) as { findings: Finding[] };
        const generatedAlerts = generateAlertsFromFindings(data.findings || []);
        setAlerts(generatedAlerts);
      } catch (err) {
        console.error('Failed to load alerts:', err);
        setAlerts([]);
      } finally {
        setLoading(false);
      }
    };

    fetchAlerts();
  }, [selectedRunId, serverConnected]);

  const filteredAlerts = filterSeverity 
    ? alerts.filter(a => a.severity === filterSeverity)
    : alerts;

  const formatTimeAgo = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    
    if (diffHours < 1) return time.justNow;
    if (diffHours < 24) return time.hoursAgo(diffHours);
    if (diffDays < 7) return time.daysAgo(diffDays);
    return date.toLocaleDateString();
  };

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
          <h1 className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>{alertsStrings.title}</h1>
          <p className={`text-sm ${TW_COLORS.textDisabled} mt-1`}>
            {alertsStrings.subtitle(alerts.length)}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={filterSeverity || ''}
            onChange={(e) => setFilterSeverity(e.target.value as Severity || null)}
            className={`px-4 py-2 ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault} text-slate-300 rounded-lg text-sm`}
          >
            <option value="">{alertsStrings.allSeverities}</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
          </select>
        </div>
      </div>

      {/* Alerts List */}
      {filteredAlerts.length > 0 ? (
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} divide-y divide-[#1E293B]`}>
          {filteredAlerts.map((alert) => {
            const colors = SEVERITY_STYLES[alert.severity];
            
            return (
              <div
                key={alert.id}
                role="button"
                tabIndex={0}
                onClick={() => navigate(`/findings?id=${encodeURIComponent(alert.finding.finding_id || alert.id)}`)}
                onKeyDown={(e) => e.key === 'Enter' && navigate(`/findings?id=${encodeURIComponent(alert.finding.finding_id || alert.id)}`)}
                className="p-5 hover:bg-[#1a2233] transition-colors cursor-pointer"
              >
                <div className="flex items-start gap-4">
                  <div className={`w-10 h-10 rounded-full ${colors.bg} flex items-center justify-center shrink-0`}>
                    {alert.severity === 'critical' ? (
                      <AlertOctagon className={`w-5 h-5 ${colors.text}`} />
                    ) : (
                      <AlertTriangle className={`w-5 h-5 ${colors.text}`} />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className={`text-sm font-medium ${TW_COLORS.textSecondary}`}>
                        {alert.title}
                      </h3>
                    </div>
                    <p className={`text-sm ${TW_COLORS.textDisabled} mb-2 line-clamp-2`}>{alert.description}</p>
                    <div className={`flex items-center gap-4 text-xs ${TW_COLORS.textDisabled}`}>
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {formatTimeAgo(alert.time)}
                      </div>
                      <span>{alert.finding.service}</span>
                      <span className="font-mono">{alert.finding.resource_id}</span>
                    </div>
                  </div>
                  <span className={`px-2 py-1 rounded text-xs capitalize ${colors.bg} ${colors.text}`}>
                    {alert.severity}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-12 text-center`}>
          <Bell className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <h3 className={`text-lg font-medium ${TW_COLORS.textSecondary} mb-2`}>{alertsStrings.noAlerts}</h3>
          <p className={TW_COLORS.textDisabled}>
            {!selectedRunId 
              ? alertsStrings.selectRunHint
              : alertsStrings.noAlertsHint}
          </p>
        </div>
      )}
    </div>
  );
}
