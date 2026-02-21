import { useState, useEffect } from 'react';
import { RefreshCw, AlertTriangle } from 'lucide-react';
import { PostureScoreCard } from '../components/dashboard/PostureScoreCard';
import { SeverityCards } from '../components/dashboard/SeverityCards';
import { ComplianceSection } from '../components/dashboard/ComplianceSection';
import { FindingsTrendChart } from '../components/dashboard/FindingsTrendChart';
import { RecentFindings } from '../components/dashboard/RecentFindings';
import { useApp } from '../context/AppContext';
import * as api from '../api/client';
import type { ScanResult, Finding, ComplianceFramework, TrendDataPoint } from '../types';
import { calculateComplianceWithControls, type FrameworkWithControls } from '../utils/compliance';
import { CLI_COMMANDS } from '../constants/app';
import { dashboard, empty, errors } from '../constants/strings';
import { TW_COLORS } from '../constants/theme';
import { toPostureScore } from '../utils/score';

// Generate trend data from runs
function generateTrendData(runs: api.Run[]): TrendDataPoint[] {
  return runs.slice(0, 10).reverse().map(run => ({
    date: run.created.split('T')[0],
    findings: run.summary?.findings_count || 0,
    critical: run.summary?.summary.critical || 0,
    high: run.summary?.summary.high || 0,
    medium: run.summary?.summary.medium || 0,
    low: run.summary?.summary.low || 0,
  }));
}

export function Dashboard() {
  const { selectedRunId, runs, serverConnected } = useApp();
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedRunId || !serverConnected) {
      setScanResult(null);
      return;
    }

    const fetchScanResult = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.getScanResult(selectedRunId) as ScanResult;
        setScanResult(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : errors.loadFailed);
        setScanResult(null);
      } finally {
        setLoading(false);
      }
    };

    fetchScanResult();
  }, [selectedRunId, serverConnected]);

  // Calculate derived data (with control details for expansion on dashboard)
  // Always use calculateComplianceWithControls so cards are expandable (shows control list)
  const complianceFrameworks: (ComplianceFramework | FrameworkWithControls)[] = scanResult?.findings?.length
    ? calculateComplianceWithControls(scanResult.findings as Finding[])
    : calculateComplianceWithControls([]);
  
  const trendData = generateTrendData(runs);

  // Previous run for delta calculation
  const previousRun = runs.length > 1 ? runs[1] : null;
  const previousSummary = previousRun?.summary?.summary;

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
        <p className={TW_COLORS.textDisabled}>
          {empty.startServerHint}
        </p>
      </div>
    );
  }

  if (!scanResult && !loading) {
    return (
      <div className="text-center py-12">
        <div className="w-16 h-16 rounded-full bg-slate-800 flex items-center justify-center mx-auto mb-4">
          <AlertTriangle className={`w-8 h-8 ${TW_COLORS.textDisabled}`} />
        </div>
        <h2 className={`text-xl font-semibold ${TW_COLORS.textSecondary} mb-2`}>{dashboard.noScanData}</h2>
        <p className={`${TW_COLORS.textDisabled} mb-4`}>
          {runs.length === 0 
            ? dashboard.noScanDataHint
            : empty.selectRunGeneric}
        </p>
        <code className={`text-sm ${TW_COLORS.textMuted} bg-slate-800 px-4 py-2 rounded-lg`}>
          {CLI_COMMANDS.scan}
        </code>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
        <h2 className={`text-xl font-semibold ${TW_COLORS.textSecondary} mb-2`}>{errors.loadFailed}</h2>
        <p className="text-red-400">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>{dashboard.title}</h1>
          <p className={`text-sm ${TW_COLORS.textDisabled} mt-1`}>
            {scanResult?.scan_date 
              ? `${dashboard.lastScanPrefix} ${new Date(scanResult.scan_date).toLocaleString()}`
              : ''}
            {scanResult?.account_id && ` • ${dashboard.accountPrefix} ${scanResult.account_id}`}
          </p>
        </div>
      </div>

      {/* Top Section: Posture Score + Severity Cards */}
      <div className="grid grid-cols-12 gap-6">
        {/* Posture Score - takes 4 columns */}
        <div className="col-span-4">
          <PostureScoreCard 
            score={toPostureScore(scanResult)}
            previousScore={toPostureScore(previousRun ? { risk_score: previousRun.summary?.risk_score, risk_score_explanation: null } : null)}
          />
        </div>
        
        {/* Severity Cards - takes 8 columns */}
        <div className="col-span-8">
          <SeverityCards 
            summary={{
              critical: scanResult?.summary?.critical || 0,
              high: scanResult?.summary?.high || 0,
              medium: scanResult?.summary?.medium || 0,
              low: scanResult?.summary?.low || 0,
              info: scanResult?.summary?.info || 0,
              skipped: scanResult?.summary?.skipped || 0,
              errors: scanResult?.summary?.errors || 0,
            }}
            previousSummary={previousSummary}
          />
        </div>
      </div>

      {/* Middle Section: Compliance */}
      <ComplianceSection frameworks={complianceFrameworks} />

      {/* Bottom Section: Trend Chart + Recent Findings */}
      <div className="grid grid-cols-12 gap-6">
        <div className="col-span-7">
          <FindingsTrendChart data={trendData} />
        </div>
        <div className="col-span-5">
          <RecentFindings findings={(scanResult?.findings || []) as Finding[]} limit={5} />
        </div>
      </div>
    </div>
  );
}
