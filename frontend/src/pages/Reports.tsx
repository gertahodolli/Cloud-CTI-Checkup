import { useState, useEffect } from 'react';
import { 
  FileText, Download, Cloud, 
  Calendar, FileJson, FileCode, Database, RefreshCw, AlertTriangle
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import * as api from '../api/client';
import { toPostureScore } from '../utils/score';
import { reports, empty } from '../constants/strings';
import { TW_COLORS } from '../constants/theme';

const formatConfig: Record<string, { icon: typeof FileJson; label: string; description: string; color: string }> = {
  json: { icon: FileJson, label: reports.formats.json.label, description: reports.formats.json.description, color: 'text-emerald-400' },
  sigma: { icon: FileCode, label: reports.formats.sigma.label, description: reports.formats.sigma.description, color: 'text-purple-400' },
  kql: { icon: Database, label: reports.formats.kql.label, description: reports.formats.kql.description, color: 'text-blue-400' },
  cloudwatch: { icon: Cloud, label: reports.formats.cloudwatch.label, description: reports.formats.cloudwatch.description, color: 'text-orange-400' },
  splunk: { icon: Database, label: reports.formats.splunk.label, description: reports.formats.splunk.description, color: 'text-green-400' }
};

function ExportCard({ file, runId }: { file: api.ExportFile; runId: string }) {
  const formatCfg = formatConfig[file.format] || formatConfig.json;
  const Icon = formatCfg.icon;

  const handleDownload = () => {
    const url = api.getExportDownloadUrl(runId, file.name);
    window.open(url, '_blank');
  };

  return (
    <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-5 ${TW_COLORS.borderHover} transition-all`}>
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg ${TW_COLORS.bgAccent} flex items-center justify-center`}>
            <Icon className={`w-5 h-5 ${formatCfg.color}`} />
          </div>
          <div>
            <h3 className={`text-sm font-medium ${TW_COLORS.textSecondary} truncate max-w-[200px]`}>{file.name}</h3>
            <span className={`text-xs ${formatCfg.color}`}>{formatCfg.label}</span>
          </div>
        </div>
      </div>

      <div className={`flex items-center gap-2 text-xs ${TW_COLORS.textDisabled} mb-4`}>
        <span>{(file.size / 1024).toFixed(1)} KB</span>
      </div>

      <button
        onClick={handleDownload}
        className={`w-full flex items-center justify-center gap-2 px-4 py-2.5 ${TW_COLORS.bgAccent} ${TW_COLORS.textAccent} rounded-lg text-sm font-medium hover:bg-amber-500/20 transition-colors`}
      >
        <Download className="w-4 h-4" />
        Download
      </button>
    </div>
  );
}

export function Reports() {
  const { selectedRunId, runs, serverConnected, selectRun } = useApp();
  const [exports, setExports] = useState<api.ExportFile[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!selectedRunId || !serverConnected) {
      setExports([]);
      return;
    }

    const fetchExports = async () => {
      setLoading(true);
      try {
        const data = await api.getExports(selectedRunId);
        setExports(data.exports);
      } catch (err) {
        console.error('Failed to load exports:', err);
        setExports([]);
      } finally {
        setLoading(false);
      }
    };

    fetchExports();
  }, [selectedRunId, serverConnected]);

  if (!serverConnected) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="w-12 h-12 text-yellow-400 mx-auto mb-4" />
        <h2 className={`text-xl font-semibold ${TW_COLORS.textSecondary} mb-2`}>{empty.serverNotConnected}</h2>
        <p className={TW_COLORS.textDisabled}>{empty.startServerHint}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>{reports.title}</h1>
          <p className={`text-sm ${TW_COLORS.textDisabled} mt-1`}>{reports.subtitle}</p>
        </div>
      </div>

      {/* Quick Export Section */}
      <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
        <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{reports.exportFormats}</h2>
        <p className={`text-sm ${TW_COLORS.textDisabled} mb-6`}>{reports.exportFormatsHint}</p>
        
        <div className="grid grid-cols-4 gap-4">
          {Object.entries(formatConfig).slice(0, 4).map(([key, cfg]) => (
            <div key={key} className={`flex flex-col items-center gap-3 p-6 ${TW_COLORS.bgSurface} rounded-xl border ${TW_COLORS.borderDefault}`}>
              <cfg.icon className={`w-8 h-8 ${cfg.color}`} />
              <div className="text-center">
                <p className={`text-sm font-medium ${TW_COLORS.textSecondary}`}>{cfg.label}</p>
                <p className={`text-xs ${TW_COLORS.textDisabled}`}>{cfg.description}</p>
              </div>
            </div>
          ))}
        </div>

        <div className={`mt-4 p-4 ${TW_COLORS.bgSurface} rounded-lg`}>
          <p className={`text-xs ${TW_COLORS.textDisabled} mb-2`}>Generate exports using the CLI:</p>
          <code className={`text-sm ${TW_COLORS.textAccent}`}>
            {reports.cliCommand}
          </code>
        </div>
      </div>

      {/* Available Exports */}
      <div>
        <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>
          {reports.availableExports}
          {selectedRunId && <span className={`text-sm font-normal ${TW_COLORS.textDisabled} ml-2`}>{reports.fromSelectedRun}</span>}
        </h2>

        {loading ? (
          <div className="flex items-center justify-center h-32">
            <RefreshCw className={`w-6 h-6 ${TW_COLORS.textAccent} animate-spin`} />
          </div>
        ) : exports.length > 0 ? (
          <div className="grid grid-cols-3 gap-6">
            {exports.map((file, index) => (
              <ExportCard key={index} file={file} runId={selectedRunId!} />
            ))}
          </div>
        ) : (
          <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-12 text-center`}>
            <FileText className="w-12 h-12 text-slate-600 mx-auto mb-4" />
            <p className={TW_COLORS.textDisabled}>
              {!selectedRunId 
                ? reports.selectRunHint
                : reports.noExports}
            </p>
          </div>
        )}
      </div>

      {/* Recent Runs */}
      <div>
        <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{reports.recentRuns}</h2>
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} divide-y divide-[#1E293B]`}>
          {runs.slice(0, 5).map((run) => (
            <div
              key={run.id}
              role="button"
              tabIndex={0}
              onClick={() => selectRun(run.id)}
              onKeyDown={(e) => e.key === 'Enter' && selectRun(run.id)}
              className="p-4 hover:bg-[#1a2233] transition-colors cursor-pointer"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className={`text-sm font-medium ${TW_COLORS.textSecondary}`}>
                    {run.name || new Date(run.created).toLocaleString()}
                  </p>
                  {run.name && (
                    <p className={`text-xs ${TW_COLORS.textDisabled} mt-0.5`}>
                      {new Date(run.created).toLocaleString()}
                    </p>
                  )}
                  {run.summary && (
                    <p className={`text-xs ${TW_COLORS.textDisabled} mt-1`}>
                      {run.summary.provider === 'cloudtrail' && (run.summary.cloudtrail_mode === 'llm' || run.summary.cloudtrail_mode === 'baseline')
                        ? (run.summary.cloudtrail_mode === 'llm' ? 'CloudTrail_AiInsights' : 'CloudTrail_Baseline')
                        : `${run.summary.findings_count} findings${run.summary.risk_score !== undefined ? ` • Score: ${toPostureScore(run.summary)}` : ''}`}
                    </p>
                  )}
                </div>
                <Calendar className={`w-4 h-4 ${TW_COLORS.textDisabled}`} />
              </div>
            </div>
          ))}
          {runs.length === 0 && (
            <div className="p-8 text-center">
              <p className={TW_COLORS.textDisabled}>{reports.noRuns}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
