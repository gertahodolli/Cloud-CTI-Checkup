import { useState, useEffect } from 'react';
import { 
  AlertTriangle, RefreshCw, Copy, Check, ExternalLink,
  Globe, Key, User, Server, MapPin, Fingerprint
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import * as api from '../api/client';
import { empty, indicators as indicatorStrings } from '../constants/strings';
import { TW_COLORS } from '../constants/theme';

interface IndicatorsData {
  runId: string;
  hasIndicators: boolean;
  indicators: api.ExtractedIndicators;
}

export function Indicators() {
  const { selectedRunId, serverConnected } = useApp();
  const navigate = useNavigate();
  const [data, setData] = useState<IndicatorsData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedRunId || !serverConnected) {
      setData(null);
      return;
    }

    const fetchIndicators = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await api.getIndicators(selectedRunId);
        setData(result);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load indicators');
        setData(null);
      } finally {
        setLoading(false);
      }
    };

    fetchIndicators();
  }, [selectedRunId, serverConnected]);

  const copyToClipboard = async (text: string, field: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const copyIPs = () => {
    if (data?.indicators.ips) {
      copyToClipboard(data.indicators.ips.join('\n'), 'ips');
    }
  };

  const copyIdentities = () => {
    if (data?.indicators.identities) {
      copyToClipboard(data.indicators.identities.join('\n'), 'identities');
    }
  };

  const copyAccessKeys = () => {
    if (data?.indicators.access_key_ids) {
      copyToClipboard(data.indicators.access_key_ids.join('\n'), 'access_keys');
    }
  };

  const useInThreatIntel = () => {
    // Navigate to Threat Intel with batch tab
    // Could potentially pass IPs via state or query params in the future
    navigate('/intel');
  };

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

  if (!selectedRunId) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>Extracted Indicators (IOCs)</h1>
          <p className={`text-sm ${TW_COLORS.textDisabled} mt-1`}>
            Deterministic extraction of IPs, identities, and access keys from CloudTrail events
          </p>
        </div>
        <div className={`text-center py-12 ${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault}`}>
          <Fingerprint className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <h2 className={`text-xl font-semibold ${TW_COLORS.textSecondary} mb-2`}>No Run Selected</h2>
          <p className={TW_COLORS.textDisabled}>Select a run with CloudTrail analysis to view extracted indicators.</p>
        </div>
      </div>
    );
  }

  if (error || !data?.hasIndicators) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>Extracted Indicators (IOCs)</h1>
          <p className={`text-sm ${TW_COLORS.textDisabled} mt-1`}>
            Deterministic extraction of IPs, identities, and access keys from CloudTrail events
          </p>
        </div>
        <div className={`text-center py-12 ${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault}`}>
          <Fingerprint className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <h2 className={`text-xl font-semibold ${TW_COLORS.textSecondary} mb-2`}>No Indicators Available</h2>
          <p className={`${TW_COLORS.textDisabled} mb-6 max-w-md mx-auto`}>
            This run doesn't have extracted indicators. Run a CloudTrail analysis to extract IOCs:
          </p>
          <code className={`text-sm ${TW_COLORS.textMuted} bg-slate-800 px-4 py-2 rounded-lg`}>
            cti-checkup ai summarize cloudtrail --events events.json
          </code>
        </div>
      </div>
    );
  }

  const { indicators } = data;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>Extracted Indicators (IOCs)</h1>
          <p className={`text-sm ${TW_COLORS.textDisabled} mt-1`}>
            Deterministic extraction from CloudTrail events using regex and field parsing
          </p>
        </div>
        <button
          onClick={useInThreatIntel}
          className="flex items-center gap-2 px-4 py-2 bg-amber-500 hover:bg-amber-600 text-white rounded-lg transition-colors"
        >
          <ExternalLink className="w-4 h-4" />
          Use in Threat Intel
        </button>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-4`}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
              <Globe className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>{indicators.ips_count}</p>
              <p className={`text-xs ${TW_COLORS.textDisabled}`}>IPs</p>
            </div>
          </div>
        </div>
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-4`}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 flex items-center justify-center">
              <Key className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <p className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>{indicators.access_key_ids_count}</p>
              <p className={`text-xs ${TW_COLORS.textDisabled}`}>Access Keys</p>
            </div>
          </div>
        </div>
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-4`}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
              <User className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>{indicators.identities_count}</p>
              <p className={`text-xs ${TW_COLORS.textDisabled}`}>Identities</p>
            </div>
          </div>
        </div>
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-4`}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
              <MapPin className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>{indicators.regions.length}</p>
              <p className={`text-xs ${TW_COLORS.textDisabled}`}>Regions</p>
            </div>
          </div>
        </div>
      </div>

      {/* IPs Section */}
      <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Globe className="w-5 h-5 text-blue-400" />
            <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary}`}>
              IP Addresses ({indicators.ips_count})
            </h2>
          </div>
          <button
            onClick={copyIPs}
            disabled={indicators.ips.length === 0}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-colors ${
              copiedField === 'ips'
                ? 'bg-green-500/20 text-green-400'
                : `${TW_COLORS.bgSurface} ${TW_COLORS.textMuted} hover:${TW_COLORS.textSecondary}`
            } ${indicators.ips.length === 0 ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {copiedField === 'ips' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            {copiedField === 'ips' ? 'Copied!' : 'Copy All'}
          </button>
        </div>
        {indicators.ips.length > 0 ? (
          <div className={`${TW_COLORS.bgSurface} rounded-lg p-4 max-h-64 overflow-y-auto font-mono text-sm`}>
            {indicators.ips.map((ip, idx) => (
              <div key={idx} className={`${TW_COLORS.textSecondary} py-0.5`}>{ip}</div>
            ))}
          </div>
        ) : (
          <p className={TW_COLORS.textDisabled}>No external IPs found in events</p>
        )}
        <p className={`text-xs ${TW_COLORS.textDisabled} mt-3`}>
          Tip: Copy IPs and paste into Threat Intel → Batch Lookup for reputation checks
        </p>
      </div>

      {/* Access Key IDs Section */}
      <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Key className="w-5 h-5 text-amber-400" />
            <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary}`}>
              Access Key IDs ({indicators.access_key_ids_count})
            </h2>
          </div>
          <button
            onClick={copyAccessKeys}
            disabled={indicators.access_key_ids.length === 0}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-colors ${
              copiedField === 'access_keys'
                ? 'bg-green-500/20 text-green-400'
                : `${TW_COLORS.bgSurface} ${TW_COLORS.textMuted} hover:${TW_COLORS.textSecondary}`
            } ${indicators.access_key_ids.length === 0 ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {copiedField === 'access_keys' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            {copiedField === 'access_keys' ? 'Copied!' : 'Copy All'}
          </button>
        </div>
        {indicators.access_key_ids.length > 0 ? (
          <div className={`${TW_COLORS.bgSurface} rounded-lg p-4 max-h-48 overflow-y-auto font-mono text-sm`}>
            {indicators.access_key_ids.map((keyId, idx) => (
              <div key={idx} className={`${TW_COLORS.textSecondary} py-0.5`}>{keyId}</div>
            ))}
          </div>
        ) : (
          <p className={TW_COLORS.textDisabled}>No access key IDs found in events</p>
        )}
        <p className={`text-xs ${TW_COLORS.textDisabled} mt-3`}>
          Keys are masked (last 4 chars shown). For key age and rotation status, run an AWS scan and check IAM findings.
        </p>
      </div>

      {/* Identities Section */}
      <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <User className="w-5 h-5 text-purple-400" />
            <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary}`}>
              Identities ({indicators.identities_count})
            </h2>
          </div>
          <button
            onClick={copyIdentities}
            disabled={indicators.identities.length === 0}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-colors ${
              copiedField === 'identities'
                ? 'bg-green-500/20 text-green-400'
                : `${TW_COLORS.bgSurface} ${TW_COLORS.textMuted} hover:${TW_COLORS.textSecondary}`
            } ${indicators.identities.length === 0 ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {copiedField === 'identities' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            {copiedField === 'identities' ? 'Copied!' : 'Copy All'}
          </button>
        </div>
        {indicators.identities.length > 0 ? (
          <div className={`${TW_COLORS.bgSurface} rounded-lg p-4 max-h-64 overflow-y-auto font-mono text-sm`}>
            {indicators.identities.map((identity, idx) => (
              <div key={idx} className={`${TW_COLORS.textSecondary} py-0.5 break-all`}>{identity}</div>
            ))}
          </div>
        ) : (
          <p className={TW_COLORS.textDisabled}>No identities found in events</p>
        )}
        <p className={`text-xs ${TW_COLORS.textDisabled} mt-3`}>
          Includes ARNs, usernames, principal IDs, and assumed roles from CloudTrail events
        </p>
      </div>

      {/* Additional Info */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Domains */}
        {indicators.domains.length > 0 && (
          <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
            <div className="flex items-center gap-3 mb-4">
              <Server className="w-5 h-5 text-cyan-400" />
              <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary}`}>
                Domains ({indicators.domains_count})
              </h2>
            </div>
            <div className={`${TW_COLORS.bgSurface} rounded-lg p-4 max-h-48 overflow-y-auto font-mono text-sm`}>
              {indicators.domains.map((domain, idx) => (
                <div key={idx} className={`${TW_COLORS.textSecondary} py-0.5`}>{domain}</div>
              ))}
            </div>
          </div>
        )}

        {/* Event Sources & Regions */}
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
          <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>Metadata</h2>
          <div className="space-y-3">
            <div>
              <p className={`text-xs font-medium ${TW_COLORS.textMuted} mb-1`}>Regions</p>
              <p className={`text-sm ${TW_COLORS.textSecondary}`}>
                {indicators.regions.length > 0 ? indicators.regions.join(', ') : '(none)'}
              </p>
            </div>
            <div>
              <p className={`text-xs font-medium ${TW_COLORS.textMuted} mb-1`}>Event Sources ({indicators.event_sources.length})</p>
              <p className={`text-sm ${TW_COLORS.textSecondary}`}>
                {indicators.event_sources.length > 0 ? indicators.event_sources.slice(0, 10).join(', ') : '(none)'}
                {indicators.event_sources.length > 10 && ` +${indicators.event_sources.length - 10} more`}
              </p>
            </div>
            <div>
              <p className={`text-xs font-medium ${TW_COLORS.textMuted} mb-1`}>Unique User Agents</p>
              <p className={`text-sm ${TW_COLORS.textSecondary}`}>{indicators.user_agents_count}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Next Steps */}
      <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-amber-400 mb-2">Next Steps</h3>
        <ul className="text-sm text-amber-400/80 space-y-1">
          <li>• Copy IPs and run them through <strong>Threat Intel → Batch Lookup</strong> for reputation checks</li>
          <li>• For <strong>long-lived access keys</strong> and <strong>key age</strong>: run an AWS scan (<code className="bg-slate-800 px-1 rounded">cti-checkup cloud aws scan</code>) and check IAM findings</li>
          <li>• Review identities for unexpected users, roles, or cross-account access</li>
        </ul>
      </div>
    </div>
  );
}
