import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Upload, FileJson, Play, AlertTriangle, CheckCircle, 
  Loader2, Fingerprint, Sparkles, Info
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import * as api from '../api/client';
import { empty, cloudtrail as cloudtrailStrings } from '../constants/strings';
import { TW_COLORS } from '../constants/theme';

type AnalysisMode = 'baseline' | 'llm';

// Configurable defaults for CloudTrail analysis
const DEFAULTS = {
  /** Polling interval in milliseconds */
  POLL_INTERVAL_MS: 1000,
  /** Analysis timeout in milliseconds (5 minutes) */
  ANALYSIS_TIMEOUT_MS: 5 * 60 * 1000,
  /** Accepted file extensions */
  ACCEPTED_EXTENSIONS: ['.json', '.jsonl'],
  /** Route after baseline analysis (IOCs) */
  BASELINE_ROUTE: '/indicators',
  /** Route after AI analysis */
  AI_ROUTE: '/ai-insights',
} as const;

export function CloudTrail() {
  const { serverConnected, refetchRuns, selectRun, cloudtrailUpload, setCloudTrailUpload } = useApp();
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  
  const file = cloudtrailUpload ? { name: cloudtrailUpload.fileName, size: cloudtrailUpload.fileSize } : null;
  const fileContent = cloudtrailUpload?.fileContent ?? null;
  const mode = cloudtrailUpload?.mode ?? 'baseline';
  const setMode = (m: AnalysisMode) => {
    if (cloudtrailUpload) setCloudTrailUpload({ ...cloudtrailUpload, mode: m });
  };
  
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<{ runId: string; message: string } | null>(null);

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (!selectedFile) return;
    
    setError(null);
    setSuccess(null);
    
    // Validate file type
    const hasValidExtension = DEFAULTS.ACCEPTED_EXTENSIONS.some(ext => 
      selectedFile.name.toLowerCase().endsWith(ext)
    );
    if (!hasValidExtension) {
      setError(cloudtrailStrings.errors.invalidFileType);
      return;
    }
    
    // Read file content
    try {
      const content = await selectedFile.text();
      
      // Basic validation - try to parse as JSON
      try {
        const parsed = JSON.parse(content);
        // Check if it's an array or has Records field
        if (!Array.isArray(parsed) && !parsed.Records) {
          setError(cloudtrailStrings.errors.invalidStructure);
          return;
        }
      } catch {
        // Could be JSONL - check if first line is valid JSON
        const firstLine = content.trim().split('\n')[0];
        try {
          JSON.parse(firstLine);
        } catch {
          setError(cloudtrailStrings.errors.invalidJsonFormat);
          return;
        }
      }
      
      setCloudTrailUpload({
        fileName: selectedFile.name,
        fileSize: selectedFile.size,
        fileContent: content,
        mode: cloudtrailUpload?.mode ?? 'baseline',
      });
    } catch {
      setError(cloudtrailStrings.errors.readFailed);
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      // Create a synthetic event to reuse the same handler
      const syntheticEvent = {
        target: { files: [droppedFile] }
      } as unknown as React.ChangeEvent<HTMLInputElement>;
      await handleFileSelect(syntheticEvent);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const startAnalysis = async () => {
    if (!fileContent) return;
    
    setIsAnalyzing(true);
    setError(null);
    setSuccess(null);
    
    try {
      const response = await api.startCloudTrailAnalysis({
        eventsContent: fileContent,
        mode,
      });
      
      if (response.success) {
        setSuccess({
          runId: response.runId,
          message: response.message
        });
        
        // Poll for completion
        const pollInterval = setInterval(async () => {
          try {
            const status = await api.getActiveScanStatus(response.runId);
            if (status.status === 'completed') {
              clearInterval(pollInterval);
              // Refresh runs and select the new one
              await refetchRuns();
              selectRun(response.runId);
              // Baseline → IOCs, AI → AI Insights
              navigate(mode === 'llm' ? DEFAULTS.AI_ROUTE : DEFAULTS.BASELINE_ROUTE);
            } else if (status.status === 'failed' || status.status === 'error') {
              clearInterval(pollInterval);
              setError(`${cloudtrailStrings.errors.analysisFailed}: ${status.errors.join(', ') || cloudtrailStrings.errors.unknownError}`);
              setIsAnalyzing(false);
            }
          } catch {
            // Scan might be done and removed from active list
            clearInterval(pollInterval);
            await refetchRuns();
            selectRun(response.runId);
            navigate(mode === 'llm' ? DEFAULTS.AI_ROUTE : DEFAULTS.BASELINE_ROUTE);
          }
        }, DEFAULTS.POLL_INTERVAL_MS);
        
        // Timeout after configured duration
        setTimeout(() => {
          clearInterval(pollInterval);
          if (isAnalyzing) {
            setError(cloudtrailStrings.errors.timeout);
            setIsAnalyzing(false);
          }
        }, DEFAULTS.ANALYSIS_TIMEOUT_MS);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : cloudtrailStrings.errors.startFailed);
      setIsAnalyzing(false);
    }
  };

  const clearFile = () => {
    setCloudTrailUpload(null);
    setError(null);
    setSuccess(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>{cloudtrailStrings.title}</h1>
        <p className={`text-sm ${TW_COLORS.textDisabled} mt-1`}>
          {cloudtrailStrings.subtitle}
        </p>
      </div>

      {/* Info Banner */}
      <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
        <div className="flex gap-3">
          <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-blue-400/90">
            <p className="font-medium mb-1">{cloudtrailStrings.info.title}</p>
            <ol className="list-decimal list-inside space-y-1 text-blue-400/70">
              {cloudtrailStrings.info.steps.map((step, idx) => (
                <li key={idx}>{step}</li>
              ))}
            </ol>
          </div>
        </div>
      </div>

      {/* Upload Section */}
      <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
        <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{cloudtrailStrings.upload.title}</h2>
        
        {/* Drop Zone */}
        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${
            file 
              ? 'border-green-500/50 bg-green-500/5' 
              : `${TW_COLORS.borderDefault} hover:border-amber-500/50 hover:bg-amber-500/5`
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept={DEFAULTS.ACCEPTED_EXTENSIONS.join(',')}
            onChange={handleFileSelect}
            className="hidden"
          />
          
          {file ? (
            <div className="space-y-2">
              <FileJson className="w-12 h-12 text-green-400 mx-auto" />
              <p className={`font-medium ${TW_COLORS.textSecondary}`}>{file.name}</p>
              <p className={`text-sm ${TW_COLORS.textDisabled}`}>
                {(file.size / 1024).toFixed(1)} KB
              </p>
              <button
                onClick={(e) => { e.stopPropagation(); clearFile(); }}
                className={`text-sm ${TW_COLORS.textMuted} hover:text-red-400 transition-colors`}
              >
                {cloudtrailStrings.upload.removeFile}
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              <Upload className={`w-12 h-12 ${TW_COLORS.textDisabled} mx-auto`} />
              <p className={TW_COLORS.textSecondary}>
                {cloudtrailStrings.upload.dropzoneText}
              </p>
              <p className={`text-sm ${TW_COLORS.textDisabled}`}>
                {cloudtrailStrings.upload.dropzoneHint}
              </p>
            </div>
          )}
        </div>

        {/* Error */}
        {error && (
          <div className="mt-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {/* Success */}
        {success && !isAnalyzing && (
          <div className="mt-4 p-3 bg-green-500/10 border border-green-500/20 rounded-lg flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
            <div className="text-sm text-green-400">
              <p className="font-medium">{success.message}</p>
              <p className="text-green-400/70">{cloudtrailStrings.success.runIdLabel}: {success.runId}</p>
            </div>
          </div>
        )}
      </div>

      {/* Analysis Options */}
      {file && (
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
          <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{cloudtrailStrings.options.title}</h2>
          
          {/* Mode Selection */}
          <div className="space-y-3">
            <label className={`text-sm font-medium ${TW_COLORS.textMuted}`}>{cloudtrailStrings.options.modeLabel}</label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Baseline Mode */}
              <button
                onClick={() => setMode('baseline')}
                className={`p-4 rounded-lg border-2 text-left transition-colors ${
                  mode === 'baseline'
                    ? 'border-amber-500 bg-amber-500/10'
                    : `${TW_COLORS.borderDefault} hover:border-amber-500/50`
                }`}
              >
                <div className="flex items-center gap-3 mb-2">
                  <Fingerprint className={`w-5 h-5 ${mode === 'baseline' ? 'text-amber-400' : TW_COLORS.textDisabled}`} />
                  <span className={`font-medium ${mode === 'baseline' ? TW_COLORS.textSecondary : TW_COLORS.textMuted}`}>
                    {cloudtrailStrings.options.baseline.name}
                  </span>
                </div>
                <p className={`text-sm ${TW_COLORS.textDisabled}`}>
                  {cloudtrailStrings.options.baseline.description}
                </p>
              </button>

              {/* AI Mode */}
              <button
                onClick={() => setMode('llm')}
                className={`p-4 rounded-lg border-2 text-left transition-colors ${
                  mode === 'llm'
                    ? 'border-amber-500 bg-amber-500/10'
                    : `${TW_COLORS.borderDefault} hover:border-amber-500/50`
                }`}
              >
                <div className="flex items-center gap-3 mb-2">
                  <Sparkles className={`w-5 h-5 ${mode === 'llm' ? 'text-amber-400' : TW_COLORS.textDisabled}`} />
                  <span className={`font-medium ${mode === 'llm' ? TW_COLORS.textSecondary : TW_COLORS.textMuted}`}>
                    {cloudtrailStrings.options.llm.name}
                  </span>
                </div>
                <p className={`text-sm ${TW_COLORS.textDisabled}`}>
                  {cloudtrailStrings.options.llm.description}
                </p>
              </button>
            </div>
          </div>

          {/* Start Analysis Button */}
          <div className="mt-6">
            <button
              onClick={startAnalysis}
              disabled={isAnalyzing || !fileContent}
              className={`flex items-center justify-center gap-2 w-full md:w-auto px-6 py-3 rounded-lg font-medium transition-colors ${
                isAnalyzing || !fileContent
                  ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                  : 'bg-amber-500 hover:bg-amber-600 text-white'
              }`}
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  {cloudtrailStrings.actions.analyzing}
                </>
              ) : (
                <>
                  <Play className="w-5 h-5" />
                  {cloudtrailStrings.actions.startAnalysis}
                </>
              )}
            </button>
            
            {isAnalyzing && (
              <p className={`text-sm ${TW_COLORS.textDisabled} mt-2`}>
                {cloudtrailStrings.info.analyzingHint}
              </p>
            )}
          </div>
        </div>
      )}

      {/* CLI Hint */}
      <div className={`${TW_COLORS.bgSurface} rounded-lg p-4`}>
        <p className={`text-sm ${TW_COLORS.textMuted} mb-2`}>{cloudtrailStrings.cliHint.label}</p>
        <code className={`text-sm ${TW_COLORS.textDisabled} bg-slate-800 px-3 py-2 rounded block`}>
          {cloudtrailStrings.cliHint.command}
        </code>
      </div>
    </div>
  );
}
