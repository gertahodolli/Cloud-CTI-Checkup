import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Bell, ChevronDown, FolderOpen, Play, Loader2, X, Pencil, Check, Trash2, Plus } from 'lucide-react';
import { useApp } from '../../context/AppContext';
import { topBar, scan } from '../../constants/strings';
import { TW_COLORS } from '../../constants/theme';
import { toPostureScore } from '../../utils/score';
import * as api from '../../api/client';

export function TopBar() {
  const navigate = useNavigate();
  const { runs, selectedRunId, selectRun, serverConnected, refetchRuns, searchQuery, setSearchQuery } = useApp();
  const [showRunsDropdown, setShowRunsDropdown] = useState(false);
  
  // Scan state
  const [isScanning, setIsScanning] = useState(false);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<api.ActiveScanDetail | null>(null);
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [editingRunId, setEditingRunId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState('');
  
  // Scan modal form state
  const [scanProfile, setScanProfile] = useState('');
  const [scanRegions, setScanRegions] = useState('');

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const q = searchQuery.trim();
    setSearchQuery(q);
    navigate('/findings');
  };

  const selectedRun = runs.find(r => r.id === selectedRunId);

  const getRunLabel = (run: api.Run) => run.name || formatRunDate(run.created);
  const getRunSublabel = (run: api.Run) => run.name ? formatRunDate(run.created) : null;

  const handleStartRename = (e: React.MouseEvent, run: api.Run) => {
    e.stopPropagation();
    setEditingRunId(run.id);
    setEditingName(run.name || '');
  };

  const handleSaveRename = async () => {
    if (!editingRunId) return;
    try {
      await api.updateRunName(editingRunId, editingName.trim());
      await refetchRuns();
    } catch (err) {
      console.error('Failed to rename run:', err);
      setScanError(err instanceof Error ? err.message : 'Failed to rename scan');
    }
    setEditingRunId(null);
    setEditingName('');
  };

  const handleCancelRename = () => {
    setEditingRunId(null);
    setEditingName('');
  };

  const handleDeleteRun = async (e: React.MouseEvent, runId: string) => {
    e.stopPropagation();
    if (!confirm('Delete this scan? This cannot be undone.')) return;
    try {
      await api.deleteRun(runId);
      const wasSelected = selectedRunId === runId;
      await refetchRuns();
      if (wasSelected) {
        const remaining = runs.filter(r => r.id !== runId);
        selectRun(remaining.length > 0 ? remaining[0].id : null);
      }
      setShowRunsDropdown(false);
    } catch (err) {
      console.error('Failed to delete run:', err);
      setScanError(err instanceof Error ? err.message : 'Failed to delete scan');
    }
  };

  const handleOpenNewScan = () => {
    setShowRunsDropdown(false);
    setShowScanModal(true);
  };

  // Poll for active scan status
  useEffect(() => {
    if (!activeScanId || !isScanning) return;
    
    const pollStatus = async () => {
      try {
        const status = await api.getActiveScanStatus(activeScanId);
        setScanStatus(status);
        
        if (status.status !== 'running') {
          setIsScanning(false);
          // Refresh runs list after scan completes
          setTimeout(() => {
            refetchRuns();
          }, 1000);
        }
      } catch (err) {
        // Scan no longer active, refresh runs
        setIsScanning(false);
        refetchRuns();
      }
    };
    
    const interval = setInterval(pollStatus, 2000);
    pollStatus(); // Initial poll
    
    return () => clearInterval(interval);
  }, [activeScanId, isScanning, refetchRuns]);

  // Start a new scan
  const handleStartScan = async () => {
    // Capture form values before closing modal
    const profile = scanProfile.trim() || undefined;
    const regionsArray = scanRegions
      .split(',')
      .map(r => r.trim())
      .filter(r => r.length > 0);
    const regions = regionsArray.length > 0 ? regionsArray : undefined;
    
    // Close modal and reset form
    setShowScanModal(false);
    setScanProfile('');
    setScanRegions('');
    
    // Start scanning
    setIsScanning(true);
    setScanError(null);
    
    try {
      const result = await api.startScan({ profile, regions });
      setActiveScanId(result.runId);
    } catch (err) {
      setIsScanning(false);
      setScanError(err instanceof Error ? err.message : 'Failed to start scan');
    }
  };

  // Cancel running scan
  const handleCancelScan = async () => {
    if (!activeScanId) return;
    
    try {
      await api.cancelScan(activeScanId);
      setIsScanning(false);
      setScanStatus(null);
      setActiveScanId(null);
    } catch (err) {
      console.error('Failed to cancel scan:', err);
    }
  };

  // Format run date for display
  const formatRunDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const topBarContent = (
    <header className={`fixed top-0 left-60 right-0 h-16 ${TW_COLORS.bgSurface}/95 backdrop-blur-sm border-b ${TW_COLORS.borderDefault} z-40 px-6 flex items-center justify-between`}>
      {/* Run Selector */}
      <div className="relative">
        <button
          onClick={() => setShowRunsDropdown(!showRunsDropdown)}
          disabled={!serverConnected}
          className={`flex flex-col items-start gap-0.5 px-3 py-2 rounded-lg ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault} ${TW_COLORS.borderHover} transition-colors disabled:opacity-50 min-w-[140px]`}
        >
          <div className="flex items-center gap-2 w-full">
            <FolderOpen className={`w-4 h-4 ${TW_COLORS.textAccent} shrink-0`} />
            <span className={`text-sm font-medium ${TW_COLORS.textSecondary} truncate`}>
              {selectedRun ? getRunLabel(selectedRun) : topBar.runSelector.noRuns}
            </span>
            <ChevronDown className={`w-4 h-4 ${TW_COLORS.textDisabled} shrink-0 transition-transform ${showRunsDropdown ? 'rotate-180' : ''}`} />
          </div>
          {selectedRun && getRunSublabel(selectedRun) && (
            <span className={`text-xs ${TW_COLORS.textDisabled} pl-6`}>{getRunSublabel(selectedRun)}</span>
          )}
        </button>

        {showRunsDropdown && (
          <div className={`absolute top-full left-0 mt-2 w-80 ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault} rounded-lg shadow-xl py-1 z-50 max-h-80 overflow-y-auto`}>
            {/* New scan button */}
            <button
              onClick={handleOpenNewScan}
              disabled={!serverConnected || isScanning}
              className={`w-full flex items-center gap-3 px-4 py-3 hover:bg-[#1a2233] transition-colors text-left border-b ${TW_COLORS.borderDefault} disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              <Plus className={`w-4 h-4 ${TW_COLORS.textAccent} shrink-0`} />
              <span className="text-sm font-medium text-amber-400">{topBar.runSelector.newScan}</span>
            </button>
            {runs.length === 0 ? (
              <div className={`px-4 py-6 text-center text-sm ${TW_COLORS.textDisabled}`}>
                {topBar.runSelector.noRuns}
              </div>
            ) : (
            runs.map((run) => (
              <div
                key={run.id}
                onClick={() => {
                  if (editingRunId !== run.id) {
                    selectRun(run.id);
                    setShowRunsDropdown(false);
                  }
                }}
                className={`w-full flex items-start gap-3 px-4 py-3 hover:bg-[#1a2233] transition-colors cursor-pointer ${
                  selectedRunId === run.id ? 'bg-amber-500/10' : ''
                }`}
              >
                <FolderOpen className={`w-4 h-4 mt-0.5 shrink-0 ${selectedRunId === run.id ? TW_COLORS.textAccent : TW_COLORS.textDisabled}`} />
                <div className="flex-1 min-w-0">
                  {editingRunId === run.id ? (
                    <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="text"
                        value={editingName}
                        onChange={(e) => setEditingName(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') handleSaveRename();
                          if (e.key === 'Escape') handleCancelRename();
                        }}
                        onBlur={handleSaveRename}
                        autoFocus
                        placeholder="Name this scan"
                        className={`flex-1 px-2 py-1 text-sm ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded ${TW_COLORS.textSecondary} focus:outline-none focus:border-amber-500/50`}
                      />
                      <button
                        type="button"
                        onClick={handleSaveRename}
                        className="p-1 rounded hover:bg-amber-500/20 text-amber-500"
                        title="Save"
                      >
                        <Check className="w-4 h-4" />
                      </button>
                    </div>
                  ) : (
                    <>
                      <p className={`text-sm font-medium ${TW_COLORS.textSecondary}`}>{getRunLabel(run)}</p>
                      {getRunSublabel(run) && (
                        <p className={`text-xs ${TW_COLORS.textDisabled} mt-0.5`}>{getRunSublabel(run)}</p>
                      )}
                      {run.summary && (
                        <div className="flex items-center gap-2 mt-1">
                          {run.summary.provider === 'cloudtrail' && (run.summary.cloudtrail_mode === 'llm' || run.summary.cloudtrail_mode === 'baseline') ? (
                            <span className={`text-xs ${TW_COLORS.textAccent}`}>
                              {run.summary.cloudtrail_mode === 'llm' ? 'CloudTrail_AiInsights' : 'CloudTrail_Baseline'}
                            </span>
                          ) : (
                            <>
                              <span className={`text-xs ${TW_COLORS.textDisabled}`}>
                                {run.summary.findings_count} findings
                              </span>
                              {run.summary?.risk_score !== undefined && (
                                <span className={`text-xs ${TW_COLORS.textAccent}`}>
                                  Score: {toPostureScore(run.summary)}
                                </span>
                              )}
                            </>
                          )}
                        </div>
                      )}
                    </>
                  )}
                </div>
                {editingRunId !== run.id && (
                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      type="button"
                      onClick={(e) => handleStartRename(e, run)}
                      className={`p-1.5 rounded hover:bg-amber-500/20 ${TW_COLORS.textDisabled} hover:text-amber-500`}
                      title="Rename scan"
                    >
                      <Pencil className="w-3.5 h-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={(e) => handleDeleteRun(e, run.id)}
                      className={`p-1.5 rounded hover:bg-red-500/20 ${TW_COLORS.textDisabled} hover:text-red-400`}
                      title={topBar.runSelector.deleteScan}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}
              </div>
            ))
            )}
          </div>
        )}
      </div>

      {/* Search Bar */}
      <form onSubmit={handleSearch} className="flex-1 max-w-xl mx-8">
        <div className="relative">
          <Search className={`absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 ${TW_COLORS.textDisabled}`} />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={topBar.searchPlaceholder}
            className={`w-full pl-10 pr-4 py-2.5 ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} placeholder:${TW_COLORS.textDisabled} focus:outline-none focus:border-amber-500/50 focus:ring-1 focus:ring-amber-500/20 transition-all`}
          />
        </div>
      </form>

      {/* Right Section */}
      <div className="flex items-center gap-3">
        {/* Scan Button */}
        {isScanning ? (
          <div className="flex items-center gap-2">
            <div className={`flex items-center gap-2 px-3 py-2 rounded-lg ${TW_COLORS.bgElevated} border border-amber-500/30`}>
              <Loader2 className="w-4 h-4 text-amber-500 animate-spin" />
              <span className="text-sm text-amber-500">{scan.scanRunning}</span>
              {scanStatus && (
                <span className={`text-xs ${TW_COLORS.textDisabled}`}>
                  ({scanStatus.outputLines} lines)
                </span>
              )}
            </div>
            <button
              onClick={handleCancelScan}
              className="p-2 rounded-lg hover:bg-red-500/10 transition-colors"
              title={scan.cancelScan}
            >
              <X className="w-4 h-4 text-red-400" />
            </button>
          </div>
        ) : (
          <button
            onClick={() => setShowScanModal(true)}
            disabled={!serverConnected}
            className="flex items-center gap-2 px-4 py-2 bg-amber-500 hover:bg-amber-600 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors"
          >
            <Play className="w-4 h-4 text-white" />
            <span className="text-sm font-medium text-white">{scan.startScan}</span>
          </button>
        )}

        {/* Scan Error Toast */}
        {scanError && (
          <div className="absolute top-20 right-6 bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 flex items-center gap-3">
            <span className="text-sm text-red-400">{scanError}</span>
            <button onClick={() => setScanError(null)}>
              <X className="w-4 h-4 text-red-400" />
            </button>
          </div>
        )}

        {/* Notifications - show count from latest run */}
        <button
          type="button"
          onClick={() => navigate('/alerts')}
          className={`relative p-2.5 rounded-lg hover:${TW_COLORS.bgElevated} transition-colors`}
          title="View alerts"
        >
          <Bell className={`w-5 h-5 ${TW_COLORS.textMuted}`} />
          {selectedRun?.summary && (selectedRun.summary.summary.critical + selectedRun.summary.summary.high) > 0 && (
            <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full" />
          )}
        </button>
      </div>

    </header>
  );

  // Close modal and reset form
  const closeScanModal = () => {
    setShowScanModal(false);
    setScanProfile('');
    setScanRegions('');
  };

  // Scan Modal - render inline with higher z-index
  const scanModal = showScanModal && (
    <div 
      className="fixed inset-0 bg-black/50 flex items-center justify-center z-[100]"
      onClick={closeScanModal}
    >
      <div 
        className={`${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-xl p-6 w-full max-w-md shadow-2xl mx-4`}
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-lg font-semibold text-white mb-1">{scan.modal.title}</h2>
        <p className={`text-sm ${TW_COLORS.textDisabled} mb-6`}>{scan.modal.subtitle}</p>
        
        <div className="space-y-4 mb-6">
          <div>
            <label className={`block text-sm font-medium ${TW_COLORS.textSecondary} mb-2`}>
              {scan.modal.profile}
            </label>
            <input
              type="text"
              value={scanProfile}
              onChange={(e) => setScanProfile(e.target.value)}
              placeholder="default"
              className={`w-full px-3 py-2 ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} placeholder:${TW_COLORS.textDisabled} focus:outline-none focus:border-amber-500/50`}
            />
            <p className={`text-xs ${TW_COLORS.textDisabled} mt-1`}>{scan.modal.profileHint}</p>
          </div>
          
          <div>
            <label className={`block text-sm font-medium ${TW_COLORS.textSecondary} mb-2`}>
              {scan.modal.regions}
            </label>
            <input
              type="text"
              value={scanRegions}
              onChange={(e) => setScanRegions(e.target.value)}
              placeholder="us-east-1, eu-west-1"
              className={`w-full px-3 py-2 ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} placeholder:${TW_COLORS.textDisabled} focus:outline-none focus:border-amber-500/50`}
            />
            <p className={`text-xs ${TW_COLORS.textDisabled} mt-1`}>{scan.modal.regionsHint}</p>
          </div>
        </div>
        
        <div className="flex gap-3">
          <button
            onClick={closeScanModal}
            className={`flex-1 px-4 py-2 ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} hover:${TW_COLORS.borderHover} transition-colors`}
          >
            {scan.modal.cancel}
          </button>
          <button
            onClick={handleStartScan}
            className="flex-1 px-4 py-2 bg-amber-500 hover:bg-amber-600 rounded-lg text-sm font-medium text-white transition-colors"
          >
            {scan.modal.start}
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <>
      {topBarContent}
      {scanModal}
    </>
  );
}
