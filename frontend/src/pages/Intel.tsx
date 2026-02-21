import { useState } from 'react';
import { Globe, Search, Loader2, AlertTriangle, CheckCircle, Hash, List, Info, ChevronDown, ChevronRight, Code, RefreshCw } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { intel, empty } from '../constants/strings';
import { TW_COLORS, SEVERITY_STYLES } from '../constants/theme';
import * as api from '../api/client';

type TabType = 'ip' | 'domain' | 'hash' | 'batch';

interface LookupResult {
  type: TabType;
  query: string;
  success: boolean;
  data: unknown;
  raw?: string;
  error?: string;
}

// Structured intel report from CLI (intel ip / intel domain)
interface IntelSummary {
  critical?: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  skipped?: number;
  errors?: number;
}

interface IntelFinding {
  finding_id?: string;
  service?: string;
  region?: string | null;
  resource_type?: string;
  resource_id?: string;
  issue?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status?: string;
  evidence?: Record<string, unknown>;
  remediation?: string | null;
}

interface IntelReport {
  provider?: string;
  account_id?: string | null;
  regions?: string[];
  checks?: { name: string; status: string; message?: string | null }[];
  findings: IntelFinding[];
  summary: IntelSummary;
  partial_failure?: boolean;
  fatal_error?: boolean;
  risk_score?: number;
  risk_score_explanation?: {
    cap?: number;
    weights?: Record<string, number>;
    counts?: Record<string, number>;
    contribution?: Record<string, number>;
  };
}

function isIntelReport(data: unknown): data is IntelReport {
  if (!data || typeof data !== 'object') return false;
  const o = data as Record<string, unknown>;
  return Array.isArray(o.findings) && o.summary != null && typeof o.summary === 'object';
}

function formatIssue(issue: string | undefined): string {
  if (!issue) return '—';
  return issue.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function formatEvidenceKey(key: string): string {
  return key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function formatEvidenceValue(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (Array.isArray(v)) {
    // Join array items; truncate if too long
    const joined = v.map(item => 
      typeof item === 'object' ? JSON.stringify(item) : String(item)
    ).join(', ');
    return joined.length > 100 ? joined.slice(0, 100) + '…' : joined;
  }
  if (typeof v === 'object') {
    // Format object as readable key-value pairs
    try {
      const entries = Object.entries(v as Record<string, unknown>);
      return entries.map(([k, val]) => `${k}: ${val}`).join(', ');
    } catch {
      return JSON.stringify(v);
    }
  }
  return String(v);
}

function getSeverityStyle(severity: string | undefined) {
  const s = (severity ?? 'info').toLowerCase();
  return SEVERITY_STYLES[s as keyof typeof SEVERITY_STYLES] ?? SEVERITY_STYLES.info;
}

// Format relative time for "last analysis" (Unix timestamp to "X days/months ago")
function formatRelativeTime(timestamp: number | undefined): string {
  if (!timestamp) return '';
  const now = Math.floor(Date.now() / 1000);
  const diff = now - timestamp;
  
  const days = Math.floor(diff / 86400);
  if (days < 1) return intel.results.vtJustNow;
  if (days < 30) return intel.results.vtDaysAgo(days);
  
  const months = Math.floor(days / 30);
  if (months < 12) return intel.results.vtMonthsAgo(months);
  
  const years = Math.floor(months / 12);
  return intel.results.vtYearsAgo(years);
}

// Check if this is a VirusTotal result and get VT-specific data
function getVirusTotalData(report: IntelReport): { 
  isVT: boolean; 
  malicious: number; 
  total: number; 
  reputation?: number;
  lastAnalysisDate?: number;
} | null {
  if (report.provider !== 'virustotal') return null;
  
  // Try to get VT data from the first finding's evidence
  const finding = report.findings[0];
  if (!finding?.evidence) return null;
  
  const evidence = finding.evidence as Record<string, unknown>;
  const malicious = typeof evidence.malicious_count === 'number' ? evidence.malicious_count : 0;
  const total = typeof evidence.total_engines === 'number' ? evidence.total_engines : 0;
  const reputation = typeof evidence.reputation === 'number' ? evidence.reputation : undefined;
  const lastAnalysisDate = typeof evidence.last_analysis_date === 'number' ? evidence.last_analysis_date : undefined;
  
  return { isVT: true, malicious, total, reputation, lastAnalysisDate };
}

export function Intel() {
  const { serverConnected } = useApp();
  const [activeTab, setActiveTab] = useState<TabType>('ip');
  
  // Input states
  const [ipInput, setIpInput] = useState('');
  const [domainInput, setDomainInput] = useState('');
  const [hashInput, setHashInput] = useState('');
  const [batchInput, setBatchInput] = useState('');
  
  // Loading states
  const [loading, setLoading] = useState(false);
  
  // Result state
  const [result, setResult] = useState<LookupResult | null>(null);
  const [batchResults, setBatchResults] = useState<api.IntelBatchIPResult | null>(null);
  const [showRawJson, setShowRawJson] = useState(false);

  // Validation patterns
  const isValidIP = (ip: string) => {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(ip)) {
      const parts = ip.split('.');
      return parts.every(part => parseInt(part, 10) <= 255);
    }
    return false;
  };

  const isValidDomain = (domain: string) => {
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    return domainRegex.test(domain);
  };

  const isValidHash = (hash: string) => {
    // MD5 (32), SHA1 (40), SHA256 (64)
    const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
    return hashRegex.test(hash);
  };

  // Lookup handlers
  const handleIPLookup = async () => {
    if (!ipInput.trim()) return;
    if (!isValidIP(ipInput.trim())) {
      setResult({ type: 'ip', query: ipInput, success: false, data: null, error: intel.ip.invalidIP });
      return;
    }
    
    setLoading(true);
    setResult(null);
    
    try {
      const response = await api.checkIP(ipInput.trim());
      setResult({
        type: 'ip',
        query: ipInput.trim(),
        success: response.success,
        data: response.result,
        raw: response.raw
      });
    } catch (err) {
      setResult({
        type: 'ip',
        query: ipInput.trim(),
        success: false,
        data: null,
        error: err instanceof Error ? err.message : 'Lookup failed'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDomainLookup = async () => {
    if (!domainInput.trim()) return;
    if (!isValidDomain(domainInput.trim())) {
      setResult({ type: 'domain', query: domainInput, success: false, data: null, error: intel.domain.invalidDomain });
      return;
    }
    
    setLoading(true);
    setResult(null);
    
    try {
      const response = await api.checkDomain(domainInput.trim());
      setResult({
        type: 'domain',
        query: domainInput.trim(),
        success: response.success,
        data: response.result,
        raw: response.raw
      });
    } catch (err) {
      setResult({
        type: 'domain',
        query: domainInput.trim(),
        success: false,
        data: null,
        error: err instanceof Error ? err.message : 'Lookup failed'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleHashLookup = async () => {
    if (!hashInput.trim()) return;
    if (!isValidHash(hashInput.trim())) {
      setResult({ type: 'hash', query: hashInput, success: false, data: null, error: intel.hash.invalidHash });
      return;
    }
    
    setLoading(true);
    setResult(null);
    
    try {
      const response = await api.checkHash(hashInput.trim().toLowerCase());
      setResult({
        type: 'hash',
        query: hashInput.trim(),
        success: response.success,
        data: response.result,
        raw: response.raw
      });
    } catch (err) {
      setResult({
        type: 'hash',
        query: hashInput.trim(),
        success: false,
        data: null,
        error: err instanceof Error ? err.message : 'Lookup failed'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleBatchLookup = async () => {
    const ips = batchInput.split('\n').map(ip => ip.trim()).filter(ip => ip);
    if (ips.length === 0) return;
    
    const invalidIPs = ips.filter(ip => !isValidIP(ip));
    if (invalidIPs.length > 0) {
      setResult({
        type: 'batch',
        query: `${ips.length} IPs`,
        success: false,
        data: null,
        error: `Invalid IPs: ${invalidIPs.slice(0, 3).join(', ')}${invalidIPs.length > 3 ? '...' : ''}`
      });
      return;
    }
    
    setLoading(true);
    setBatchResults(null);
    setResult(null);
    
    try {
      const response = await api.checkIPBatch(ips);
      setBatchResults(response);
    } catch (err) {
      setResult({
        type: 'batch',
        query: `${ips.length} IPs`,
        success: false,
        data: null,
        error: err instanceof Error ? err.message : 'Batch lookup failed'
      });
    } finally {
      setLoading(false);
    }
  };

  const tabs = [
    { id: 'ip' as TabType, label: intel.tabs.ip, icon: Globe },
    { id: 'domain' as TabType, label: intel.tabs.domain, icon: Search },
    { id: 'hash' as TabType, label: intel.tabs.hash, icon: Hash },
    { id: 'batch' as TabType, label: intel.tabs.batch, icon: List },
  ];

  if (!serverConnected) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <Globe className={`w-16 h-16 ${TW_COLORS.textDisabled} mb-4`} />
        <h2 className={`text-lg font-medium ${TW_COLORS.textSecondary} mb-2`}>{empty.serverNotConnected}</h2>
        <p className={TW_COLORS.textDisabled}>{empty.startServerHint}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold text-white mb-1">{intel.title}</h1>
        <p className={TW_COLORS.textDisabled}>{intel.subtitle}</p>
      </div>

      {/* Tabs */}
      <div className={`border-b ${TW_COLORS.borderDefault}`}>
        <div className="flex gap-1">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => {
                setActiveTab(tab.id);
                setResult(null);
                setBatchResults(null);
                setShowRawJson(false);
              }}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-amber-500 text-amber-500'
                  : `border-transparent ${TW_COLORS.textMuted} hover:${TW_COLORS.textSecondary}`
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Section */}
        <div className={`${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-xl p-6`}>
          {/* IP Tab */}
          {activeTab === 'ip' && (
            <div className="space-y-4">
              <div>
                <h2 className={`text-lg font-medium ${TW_COLORS.textSecondary} mb-1`}>{intel.ip.title}</h2>
                <p className={`text-sm ${TW_COLORS.textDisabled}`}>{intel.ip.lookupHint}</p>
              </div>
              <div className="flex gap-3">
                <input
                  type="text"
                  value={ipInput}
                  onChange={(e) => setIpInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleIPLookup()}
                  placeholder={intel.ip.placeholder}
                  className={`flex-1 px-4 py-3 ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} placeholder:${TW_COLORS.textDisabled} focus:outline-none focus:border-amber-500/50`}
                />
                <button
                  onClick={handleIPLookup}
                  disabled={loading || !ipInput.trim()}
                  className="px-6 py-3 bg-amber-500 hover:bg-amber-600 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-sm font-medium text-white transition-colors flex items-center gap-2"
                >
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                  {intel.ip.lookupButton}
                </button>
              </div>
            </div>
          )}

          {/* Domain Tab */}
          {activeTab === 'domain' && (
            <div className="space-y-4">
              <div>
                <h2 className={`text-lg font-medium ${TW_COLORS.textSecondary} mb-1`}>{intel.domain.title}</h2>
                <p className={`text-sm ${TW_COLORS.textDisabled}`}>{intel.domain.lookupHint}</p>
              </div>
              <div className="flex gap-3">
                <input
                  type="text"
                  value={domainInput}
                  onChange={(e) => setDomainInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleDomainLookup()}
                  placeholder={intel.domain.placeholder}
                  className={`flex-1 px-4 py-3 ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} placeholder:${TW_COLORS.textDisabled} focus:outline-none focus:border-amber-500/50`}
                />
                <button
                  onClick={handleDomainLookup}
                  disabled={loading || !domainInput.trim()}
                  className="px-6 py-3 bg-amber-500 hover:bg-amber-600 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-sm font-medium text-white transition-colors flex items-center gap-2"
                >
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                  {intel.domain.lookupButton}
                </button>
              </div>
            </div>
          )}

          {/* Hash Tab (VirusTotal) */}
          {activeTab === 'hash' && (
            <div className="space-y-4">
              <div>
                <h2 className={`text-lg font-medium ${TW_COLORS.textSecondary} mb-1`}>{intel.hash.title}</h2>
                <p className={`text-sm ${TW_COLORS.textDisabled}`}>{intel.hash.lookupHint}</p>
              </div>
              <div className="flex gap-3">
                <input
                  type="text"
                  value={hashInput}
                  onChange={(e) => setHashInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleHashLookup()}
                  placeholder={intel.hash.placeholder}
                  className={`flex-1 px-4 py-3 ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} placeholder:${TW_COLORS.textDisabled} focus:outline-none focus:border-amber-500/50 font-mono`}
                />
                <button
                  onClick={handleHashLookup}
                  disabled={loading || !hashInput.trim()}
                  className="px-6 py-3 bg-amber-500 hover:bg-amber-600 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-sm font-medium text-white transition-colors flex items-center gap-2"
                >
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                  {intel.hash.lookupButton}
                </button>
              </div>
              <p className={`text-xs ${TW_COLORS.textDisabled}`}>
                Powered by VirusTotal. Supports MD5, SHA1, and SHA256 hashes.
              </p>
            </div>
          )}

          {/* Batch Tab */}
          {activeTab === 'batch' && (
            <div className="space-y-4">
              <div>
                <h2 className={`text-lg font-medium ${TW_COLORS.textSecondary} mb-1`}>{intel.batch.title}</h2>
                <p className={`text-sm ${TW_COLORS.textDisabled}`}>{intel.batch.lookupHint}</p>
              </div>
              <textarea
                value={batchInput}
                onChange={(e) => setBatchInput(e.target.value)}
                placeholder={intel.batch.placeholder}
                rows={6}
                className={`w-full px-4 py-3 ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} placeholder:${TW_COLORS.textDisabled} focus:outline-none focus:border-amber-500/50 font-mono resize-none`}
              />
              <button
                onClick={handleBatchLookup}
                disabled={loading || !batchInput.trim()}
                className="w-full px-6 py-3 bg-amber-500 hover:bg-amber-600 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-sm font-medium text-white transition-colors flex items-center justify-center gap-2"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                {intel.batch.lookupButton}
              </button>
            </div>
          )}
        </div>

        {/* Results Section */}
        <div className={`${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-xl p-6`}>
          <h2 className={`text-lg font-medium ${TW_COLORS.textSecondary} mb-4`}>{intel.results.title}</h2>
          
          {loading && (
            <div className="flex flex-col items-center justify-center py-12">
              <Loader2 className="w-8 h-8 text-amber-500 animate-spin mb-4" />
              <p className={TW_COLORS.textDisabled}>{intel.results.loading}</p>
            </div>
          )}

          {!loading && !result && !batchResults && (
            <div className="flex flex-col items-center justify-center py-12">
              <Info className={`w-12 h-12 ${TW_COLORS.textDisabled} mb-4`} />
              <p className={`${TW_COLORS.textMuted} mb-1`}>{intel.results.noResults}</p>
              <p className={`text-sm ${TW_COLORS.textDisabled}`}>{intel.results.noResultsHint}</p>
            </div>
          )}

          {/* Single Result */}
          {!loading && result && (
            <div className="space-y-4">
              {/* Status */}
              <div className={`flex items-center gap-2 px-4 py-3 rounded-lg ${
                result.success ? 'bg-green-500/10 border border-green-500/30' : 'bg-red-500/10 border border-red-500/30'
              }`}>
                {result.success ? (
                  <CheckCircle className="w-5 h-5 text-green-400" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                )}
                <span className={result.success ? 'text-green-400' : 'text-red-400'}>
                  {result.success ? `Results for ${result.query}` : result.error}
                </span>
              </div>

              {/* Structured report (summary + findings) */}
              {result.success && result.data && isIntelReport(result.data) && (
                <>
                  {/* Warnings */}
                  {(result.data.partial_failure || result.data.fatal_error) && (
                    <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 text-sm">
                      <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                      {result.data.fatal_error ? intel.results.fatalError : intel.results.partialFailure}
                    </div>
                  )}

                  {/* Summary strip - VT-specific or generic */}
                  {(() => {
                    const vtData = getVirusTotalData(result.data);
                    if (vtData) {
                      // VirusTotal-specific summary
                      return (
                        <div className={`px-4 py-3 ${TW_COLORS.bgElevated} rounded-lg border ${TW_COLORS.borderDefault}`}>
                          {/* Main VT detection line */}
                          <div className={`text-sm font-medium mb-2 ${vtData.malicious > 0 ? 'text-red-400' : 'text-green-400'}`}>
                            {intel.results.vtVendorsFlagged(vtData.malicious, vtData.total)}
                          </div>
                          
                          {/* Stats row */}
                          <div className="flex flex-wrap items-center gap-4 text-sm">
                            {/* Detection ratio / Risk score */}
                            {typeof result.data.risk_score === 'number' && (
                              <div className="flex items-baseline gap-2">
                                <span className={`text-xs ${TW_COLORS.textDisabled}`}>{intel.results.vtDetectionRatio}</span>
                                <span className="font-semibold text-white">
                                  {result.data.risk_score}%
                                </span>
                              </div>
                            )}
                            
                            {/* Community score */}
                            {vtData.reputation !== undefined && (
                              <div className="flex items-baseline gap-2">
                                <span className={`text-xs ${TW_COLORS.textDisabled}`}>{intel.results.vtCommunityScore}</span>
                                <span className={`font-medium ${vtData.reputation < 0 ? 'text-red-400' : vtData.reputation > 0 ? 'text-green-400' : TW_COLORS.textSecondary}`}>
                                  {vtData.reputation}
                                </span>
                              </div>
                            )}
                            
                            {/* Last analysis */}
                            {vtData.lastAnalysisDate && (
                              <div className="flex items-baseline gap-2">
                                <span className={`text-xs ${TW_COLORS.textDisabled}`}>{intel.results.vtLastAnalysis}</span>
                                <span className={TW_COLORS.textSecondary}>
                                  {formatRelativeTime(vtData.lastAnalysisDate)}
                                </span>
                              </div>
                            )}
                            
                            {/* Check again button */}
                            <button
                              onClick={() => {
                                if (result.type === 'hash') {
                                  handleHashLookup();
                                }
                              }}
                              disabled={loading}
                              className="flex items-center gap-1 px-2 py-1 text-xs text-amber-400 hover:text-amber-300 transition-colors"
                            >
                              <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
                              {intel.results.vtCheckAgain}
                            </button>
                          </div>
                        </div>
                      );
                    }
                    
                    // Generic summary strip
                    return (
                      <div className={`flex flex-wrap items-center gap-4 px-4 py-3 ${TW_COLORS.bgElevated} rounded-lg border ${TW_COLORS.borderDefault}`}>
                        {typeof result.data.risk_score === 'number' && result.data.risk_score_explanation?.cap != null && (
                          <div className="flex items-baseline gap-2">
                            <span className={`text-xs ${TW_COLORS.textDisabled}`}>{intel.results.riskScore}</span>
                            <span className="font-semibold text-white">
                              {intel.results.riskScoreOutOf(result.data.risk_score, result.data.risk_score_explanation.cap)}
                            </span>
                          </div>
                        )}
                        <div className="flex items-baseline gap-2">
                          <span className={`text-xs ${TW_COLORS.textDisabled}`}>{intel.results.findingsSummary}</span>
                          <span className={`text-sm ${TW_COLORS.textSecondary}`}>
                            {intel.results.findingsCounts(
                              result.data.summary.critical ?? 0,
                              result.data.summary.high ?? 0,
                              result.data.summary.medium ?? 0,
                              result.data.summary.low ?? 0,
                              result.data.summary.info ?? 0
                            )}
                          </span>
                        </div>
                      </div>
                    );
                  })()}

                  {/* Findings list */}
                  {result.data.findings.length === 0 ? (
                    <p className={`text-sm ${TW_COLORS.textDisabled} py-2`}>{intel.results.noFindings}</p>
                  ) : (
                    <div className="space-y-3 max-h-80 overflow-y-auto">
                      {result.data.findings.map((finding, idx) => {
                        const sev = getSeverityStyle(finding.severity);
                        return (
                          <div
                            key={finding.finding_id ?? idx}
                            className={`p-4 ${TW_COLORS.bgElevated} rounded-lg border ${TW_COLORS.borderDefault}`}
                          >
                            <div className="flex flex-wrap items-center gap-2 mb-2">
                              <span className={`px-2 py-0.5 rounded text-xs font-medium ${sev.bg} ${sev.text}`}>
                                {finding.severity ?? 'info'}
                              </span>
                              {finding.resource_id && (
                                <span className={`font-mono text-sm ${TW_COLORS.textSecondary}`}>{finding.resource_id}</span>
                              )}
                              {finding.issue && (
                                <span className={`text-xs ${TW_COLORS.textMuted}`}>{formatIssue(finding.issue)}</span>
                              )}
                            </div>
                            {finding.evidence && Object.keys(finding.evidence).length > 0 && (
                              <div className="mb-2">
                                <p className={`text-xs font-medium ${TW_COLORS.textMuted} mb-1`}>{intel.results.evidence}</p>
                                <dl className="grid grid-cols-1 gap-y-1 text-sm">
                                  {Object.entries(finding.evidence).map(([k, v]) => (
                                    <div key={k} className="flex flex-wrap gap-x-2 min-w-0">
                                      <dt className={`${TW_COLORS.textDisabled} shrink-0`}>{formatEvidenceKey(k)}:</dt>
                                      <dd className={`${TW_COLORS.textSecondary} min-w-0 break-all`}>
                                        {formatEvidenceValue(v)}
                                      </dd>
                                    </div>
                                  ))}
                                </dl>
                              </div>
                            )}
                            {finding.remediation && (
                              <p className={`text-xs ${TW_COLORS.textMuted} mt-2 pt-2 border-t ${TW_COLORS.borderDefault}`}>
                                <span className={`font-medium ${TW_COLORS.textSecondary}`}>{intel.results.remediation}</span>
                                {' '}{finding.remediation}
                              </p>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {/* Raw JSON toggle */}
                  <div>
                    <button
                      type="button"
                      onClick={() => setShowRawJson((v) => !v)}
                      className="flex items-center gap-2 text-sm text-slate-400 hover:text-slate-200 transition-colors"
                    >
                      {showRawJson ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                      <Code className="w-4 h-4" />
                      {showRawJson ? intel.results.hideRawJson : intel.results.showRawJson}
                    </button>
                    {showRawJson && (
                      <div className={`mt-2 p-4 ${TW_COLORS.bgElevated} rounded-lg overflow-auto max-h-64 border ${TW_COLORS.borderDefault}`}>
                        <pre className={`text-xs ${TW_COLORS.textMuted} font-mono whitespace-pre-wrap`}>
                          {JSON.stringify(result.data, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                </>
              )}

              {/* Fallback: raw JSON when not structured report */}
              {result.success && result.data && !isIntelReport(result.data) && (
                <div className={`p-4 ${TW_COLORS.bgElevated} rounded-lg overflow-auto max-h-96`}>
                  <pre className={`text-xs ${TW_COLORS.textMuted} font-mono whitespace-pre-wrap`}>
                    {typeof result.data === 'object'
                      ? JSON.stringify(result.data, null, 2)
                      : String(result.data)}
                  </pre>
                </div>
              )}

              {/* Raw output if no structured data at all */}
              {result.success && !result.data && result.raw && (
                <div className={`p-4 ${TW_COLORS.bgElevated} rounded-lg overflow-auto max-h-96`}>
                  <pre className={`text-xs ${TW_COLORS.textMuted} font-mono whitespace-pre-wrap`}>
                    {result.raw}
                  </pre>
                </div>
              )}

              {/* Error hint */}
              {!result.success && (
                <p className={`text-sm ${TW_COLORS.textDisabled}`}>{intel.results.errorHint}</p>
              )}
            </div>
          )}

          {/* Batch Results */}
          {!loading && batchResults && (
            <div className="space-y-4">
              {/* Summary */}
              <div className="grid grid-cols-3 gap-4">
                <div className={`p-4 ${TW_COLORS.bgElevated} rounded-lg text-center`}>
                  <p className={`text-2xl font-semibold ${TW_COLORS.textSecondary}`}>{batchResults.total}</p>
                  <p className={`text-xs ${TW_COLORS.textDisabled}`}>Total</p>
                </div>
                <div className={`p-4 ${TW_COLORS.bgElevated} rounded-lg text-center`}>
                  <p className="text-2xl font-semibold text-green-400">{batchResults.successful}</p>
                  <p className={`text-xs ${TW_COLORS.textDisabled}`}>Successful</p>
                </div>
                <div className={`p-4 ${TW_COLORS.bgElevated} rounded-lg text-center`}>
                  <p className="text-2xl font-semibold text-red-400">{batchResults.failed}</p>
                  <p className={`text-xs ${TW_COLORS.textDisabled}`}>Failed</p>
                </div>
              </div>

              {/* Individual Results */}
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {batchResults.results.map((item, index) => (
                  <div
                    key={index}
                    className={`flex items-center gap-3 px-4 py-3 ${TW_COLORS.bgElevated} rounded-lg`}
                  >
                    {item.success ? (
                      <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
                    )}
                    <span className={`font-mono text-sm ${TW_COLORS.textSecondary}`}>{item.ip}</span>
                    {item.error && (
                      <span className={`text-xs ${TW_COLORS.textDisabled} truncate`}>{item.error}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
