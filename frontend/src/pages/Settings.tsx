import { useState, useEffect } from 'react';
import { 
  Settings as SettingsIcon, Cloud, Sparkles, FileCode, FolderOpen, Code, Key,
  Save, RefreshCw, AlertTriangle, CheckCircle, Eye, EyeOff
} from 'lucide-react';
import { useApi } from '../hooks/useApi';
import * as api from '../api/client';
import { settings as settingsStrings, common, actions } from '../constants/strings';
import { DEFAULT_PATHS } from '../constants/app';
import { TW_COLORS } from '../constants/theme';

type TabId = 'general' | 'aws' | 'ai' | 'apikeys' | 'export' | 'paths' | 'advanced';

const tabs: { id: TabId; label: string; icon: typeof SettingsIcon }[] = [
  { id: 'general', label: settingsStrings.tabs.general, icon: SettingsIcon },
  { id: 'aws', label: settingsStrings.tabs.aws, icon: Cloud },
  { id: 'ai', label: settingsStrings.tabs.ai, icon: Sparkles },
  { id: 'apikeys', label: settingsStrings.tabs.apikeys, icon: Key },
  { id: 'export', label: settingsStrings.tabs.export, icon: FileCode },
  { id: 'paths', label: settingsStrings.tabs.paths, icon: FolderOpen },
  { id: 'advanced', label: settingsStrings.tabs.advanced, icon: Code },
];

// ============ Tab Components ============

function GeneralTab({ uiConfig, setUIConfig }: { 
  uiConfig: api.UIConfig; 
  setUIConfig: (c: api.UIConfig) => void;
}) {
  return (
    <div className="space-y-6">
      <div>
        <h3 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{settingsStrings.general.title}</h3>
        <p className={`text-sm ${TW_COLORS.textDisabled} mb-6`}>Basic application preferences (stored in ui_config.json)</p>
      </div>

      <div className="space-y-4">
        <div>
          <label className={`block text-sm font-medium text-slate-300 mb-2`}>{settingsStrings.general.timezone}</label>
          <select 
            value={uiConfig.timezone}
            onChange={(e) => setUIConfig({ ...uiConfig, timezone: e.target.value })}
            className={`w-full px-4 py-2.5 ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} focus:outline-none focus:border-amber-500/50`}
          >
            <option value="UTC">UTC</option>
            <option value="America/New_York">America/New_York</option>
            <option value="America/Los_Angeles">America/Los_Angeles</option>
            <option value="Europe/London">Europe/London</option>
            <option value="Europe/Paris">Europe/Paris</option>
            <option value="Asia/Tokyo">Asia/Tokyo</option>
          </select>
          <p className={`text-xs ${TW_COLORS.textDisabled} mt-1`}>{settingsStrings.general.timezoneHint}</p>
        </div>

        <div>
          <label className={`block text-sm font-medium text-slate-300 mb-2`}>{settingsStrings.general.theme}</label>
          <select 
            value={uiConfig.theme}
            onChange={(e) => setUIConfig({ ...uiConfig, theme: e.target.value as 'dark' | 'light' })}
            className={`w-full px-4 py-2.5 ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} focus:outline-none focus:border-amber-500/50`}
          >
            <option value="dark">Dark</option>
            <option value="light">Light (coming soon)</option>
          </select>
          <p className={`text-xs ${TW_COLORS.textDisabled} mt-1`}>{settingsStrings.general.themeHint}</p>
        </div>
      </div>
    </div>
  );
}

function AWSTab({ uiConfig, setUIConfig, yamlConfig, setYamlConfig }: { 
  uiConfig: api.UIConfig; 
  setUIConfig: (c: api.UIConfig) => void;
  yamlConfig: Record<string, unknown>;
  setYamlConfig: (c: Record<string, unknown>) => void;
}) {
  const { data: awsStatus } = useApi(() => api.getAWSStatus(), []);
  const { data: profilesData, loading: profilesLoading } = useApi(() => api.getAWSProfiles(), []);
  const { data: regionsData } = useApi(() => api.getAWSRegions(), []);

  const awsConfig = (yamlConfig.aws || {}) as Record<string, unknown>;
  const checksConfig = (awsConfig.checks || {}) as Record<string, { enabled?: boolean }>;
  const selectedRegions = (awsConfig.regions || []) as string[];

  const updateAwsConfig = (key: string, value: unknown) => {
    setYamlConfig({
      ...yamlConfig,
      aws: { ...awsConfig, [key]: value }
    });
  };

  const toggleCheck = (service: string) => {
    const current = checksConfig[service]?.enabled ?? true;
    setYamlConfig({
      ...yamlConfig,
      aws: {
        ...awsConfig,
        checks: {
          ...checksConfig,
          [service]: { ...checksConfig[service], enabled: !current }
        }
      }
    });
  };

  const toggleRegion = (region: string) => {
    const newRegions = selectedRegions.includes(region)
      ? selectedRegions.filter(r => r !== region)
      : [...selectedRegions, region];
    updateAwsConfig('regions', newRegions);
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{settingsStrings.aws.title}</h3>
        <p className={`text-sm ${TW_COLORS.textDisabled} mb-6`}>Configure AWS profile and scan settings</p>
      </div>

      {/* AWS Status */}
      <div className={`p-4 rounded-lg border ${awsStatus?.configured ? 'bg-green-500/5 border-green-500/20' : 'bg-yellow-500/5 border-yellow-500/20'}`}>
        <div className="flex items-center gap-2">
          {awsStatus?.configured ? (
            <CheckCircle className="w-5 h-5 text-green-400" />
          ) : (
            <AlertTriangle className="w-5 h-5 text-yellow-400" />
          )}
          <span className={`text-sm font-medium ${awsStatus?.configured ? 'text-green-400' : 'text-yellow-400'}`}>
            {awsStatus?.configured ? 'AWS CLI configured' : 'AWS CLI not configured'}
          </span>
        </div>
        {awsStatus && (
          <p className={`text-xs ${TW_COLORS.textDisabled} mt-2`}>
            Config: {awsStatus.configPath} ({awsStatus.configExists ? 'exists' : 'missing'})
          </p>
        )}
      </div>

      {/* Hint when config is missing */}
      {awsStatus && !awsStatus.configured && (
        <div className="p-4 rounded-lg border border-blue-500/20 bg-blue-500/5">
          <p className={`text-xs ${TW_COLORS.textMuted} mb-1`}>{settingsStrings.aws.configPathHint}</p>
          <p className="text-xs text-slate-400">{settingsStrings.aws.notConfiguredHint}</p>
        </div>
      )}

      {/* Profile Selector */}
      <div>
        <label className={`block text-sm font-medium text-slate-300 mb-2`}>{settingsStrings.aws.profile}</label>
        <select 
          value={uiConfig.awsProfile || ''}
          onChange={(e) => setUIConfig({ ...uiConfig, awsProfile: e.target.value || null })}
          className={`w-full px-4 py-2.5 ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} focus:outline-none focus:border-amber-500/50`}
          disabled={profilesLoading}
        >
          <option value="">Use default credential chain</option>
          {profilesData?.profiles.map(profile => (
            <option key={profile.name} value={profile.name}>
              {profile.name} {profile.hasCredentials ? '(credentials)' : '(config only)'}
            </option>
          ))}
        </select>
        <p className={`text-xs ${TW_COLORS.textDisabled} mt-1`}>{settingsStrings.aws.profileHint}</p>
      </div>

      {/* Regions */}
      <div>
        <label className={`block text-sm font-medium text-slate-300 mb-2`}>{settingsStrings.aws.regions}</label>
        <div className="grid grid-cols-3 gap-2">
          {regionsData?.regions.slice(0, 12).map(region => (
            <button
              key={region.code}
              onClick={() => toggleRegion(region.code)}
              className={`px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                selectedRegions.includes(region.code)
                  ? `${TW_COLORS.bgAccent} ${TW_COLORS.textAccent} border border-amber-500/30`
                  : `${TW_COLORS.bgSurface} ${TW_COLORS.textMuted} border ${TW_COLORS.borderDefault} ${TW_COLORS.borderHover}`
              }`}
            >
              {region.code}
            </button>
          ))}
        </div>
        <p className={`text-xs ${TW_COLORS.textDisabled} mt-2`}>{settingsStrings.aws.regionsHint}</p>
      </div>

      {/* Service Checks */}
      <div>
        <label className={`block text-sm font-medium text-slate-300 mb-2`}>{settingsStrings.aws.services}</label>
        <div className="space-y-2">
          {['s3', 'iam', 'ec2'].map(service => (
            <label key={service} className={`flex items-center justify-between p-3 ${TW_COLORS.bgSurface} rounded-lg border ${TW_COLORS.borderDefault}`}>
              <span className="text-sm text-slate-300 uppercase">{service}</span>
              <input
                type="checkbox"
                checked={checksConfig[service]?.enabled ?? true}
                onChange={() => toggleCheck(service)}
                className="w-4 h-4 rounded border-slate-600 text-amber-500 focus:ring-amber-500/20"
              />
            </label>
          ))}
        </div>
        <p className={`text-xs ${TW_COLORS.textDisabled} mt-2`}>{settingsStrings.aws.servicesHint}</p>
      </div>
    </div>
  );
}

function AITab({ yamlConfig, setYamlConfig }: { 
  yamlConfig: Record<string, unknown>;
  setYamlConfig: (c: Record<string, unknown>) => void;
}) {
  const { data: secretsStatus, refetch: refetchSecrets } = useApi(() => api.getSecretsStatus(), []);
  const [showApiKey, setShowApiKey] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [saving, setSaving] = useState(false);

  const aiConfig = (yamlConfig.ai || {}) as Record<string, unknown>;

  const updateAiConfig = (key: string, value: unknown) => {
    setYamlConfig({
      ...yamlConfig,
      ai: { ...aiConfig, [key]: value }
    });
  };

  const handleSaveApiKey = async () => {
    if (!apiKeyInput) return;
    setSaving(true);
    try {
      await api.setSecret('CTICHECKUP_AI_OPENAI_API_KEY', apiKeyInput);
      setApiKeyInput('');
      refetchSecrets();
    } catch (err) {
      console.error('Failed to save API key:', err);
    } finally {
      setSaving(false);
    }
  };

  const currentKeyStatus = secretsStatus?.secrets['CTICHECKUP_AI_OPENAI_API_KEY'];

  return (
    <div className="space-y-6">
      <div>
        <h3 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{settingsStrings.ai.title}</h3>
        <p className={`text-sm ${TW_COLORS.textDisabled} mb-6`}>Configure AI provider for CloudTrail analysis</p>
      </div>

      {/* Enable/Disable */}
      <div className={`flex items-center justify-between p-4 ${TW_COLORS.bgSurface} rounded-lg border ${TW_COLORS.borderDefault}`}>
        <div>
          <p className="text-sm font-medium text-slate-300">Enable AI Features</p>
          <p className={`text-xs ${TW_COLORS.textDisabled}`}>Use LLM for CloudTrail event summarization</p>
        </div>
        <label className="relative inline-flex items-center cursor-pointer">
          <input 
            type="checkbox" 
            checked={aiConfig.enabled as boolean || false}
            onChange={(e) => updateAiConfig('enabled', e.target.checked)}
            className="sr-only peer" 
          />
          <div className={`w-11 h-6 ${TW_COLORS.bgSurface} peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-slate-400 after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-amber-500 peer-checked:after:bg-white`}></div>
        </label>
      </div>

      {/* Provider Info */}
      <div className={`p-4 ${TW_COLORS.bgSurface} rounded-lg border ${TW_COLORS.borderDefault}`}>
        <p className="text-sm font-medium text-slate-300 mb-1">Provider: OpenAI</p>
        <p className={`text-xs ${TW_COLORS.textDisabled}`}>{settingsStrings.ai.providerHint}</p>
      </div>

      {/* API Key */}
      <div>
        <label className={`block text-sm font-medium text-slate-300 mb-2`}>{settingsStrings.ai.apiKey}</label>
        <div className={`p-4 rounded-lg border ${currentKeyStatus?.configured ? 'bg-green-500/5 border-green-500/20' : `${TW_COLORS.bgSurface} ${TW_COLORS.borderDefault}`}`}>
          {currentKeyStatus?.configured ? (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400" />
                <span className="text-sm text-green-400">{common.configured}</span>
                <span className={`text-xs ${TW_COLORS.textDisabled}`}>{currentKeyStatus.masked}</span>
                {currentKeyStatus.source && currentKeyStatus.source !== 'user' && (
                  <span className={`text-xs ${TW_COLORS.textDisabled} italic`}>
                    ({currentKeyStatus.source === 'project' ? 'from project .env' : 'from shell env'})
                  </span>
                )}
              </div>
              <button
                onClick={async () => {
                  await api.deleteSecret('CTICHECKUP_AI_OPENAI_API_KEY');
                  refetchSecrets();
                }}
                className="text-xs text-red-400 hover:text-red-300"
              >
                Remove
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="relative">
                <input
                  type={showApiKey ? 'text' : 'password'}
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                  placeholder={settingsStrings.ai.apiKeyPlaceholder}
                  className={`w-full px-4 py-2.5 pr-10 ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} focus:outline-none focus:border-amber-500/50`}
                />
                <button
                  onClick={() => setShowApiKey(!showApiKey)}
                  className={`absolute right-3 top-1/2 -translate-y-1/2 ${TW_COLORS.textDisabled} hover:${TW_COLORS.textMuted}`}
                >
                  {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <button
                onClick={handleSaveApiKey}
                disabled={!apiKeyInput || saving}
                className="px-4 py-2 bg-amber-500 hover:bg-amber-600 disabled:opacity-50 text-slate-900 text-sm font-medium rounded-lg transition-colors"
              >
                {saving ? 'Saving...' : `${actions.save} API Key`}
              </button>
            </div>
          )}
        </div>
        <p className={`text-xs ${TW_COLORS.textDisabled} mt-2`}>
          {settingsStrings.ai.apiKeyHint(secretsStatus?.projectEnvPath ?? secretsStatus?.envPath ?? 'project .env')}
        </p>
      </div>

      {/* Model Settings */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className={`block text-sm font-medium text-slate-300 mb-2`}>{settingsStrings.ai.model}</label>
          <input
            type="text"
            value={(aiConfig.model as string) || 'gpt-4'}
            onChange={(e) => updateAiConfig('model', e.target.value)}
            className={`w-full px-4 py-2.5 ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} focus:outline-none focus:border-amber-500/50`}
          />
          <p className={`text-xs ${TW_COLORS.textDisabled} mt-1`}>{settingsStrings.ai.modelHint}</p>
        </div>
        <div>
          <label className={`block text-sm font-medium text-slate-300 mb-2`}>Temperature</label>
          <input
            type="number"
            step="0.1"
            min="0"
            max="2"
            value={(aiConfig.temperature as number) ?? 0.2}
            onChange={(e) => updateAiConfig('temperature', parseFloat(e.target.value))}
            className={`w-full px-4 py-2.5 ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} focus:outline-none focus:border-amber-500/50`}
          />
        </div>
        <div>
          <label className={`block text-sm font-medium text-slate-300 mb-2`}>Max Tokens</label>
          <input
            type="number"
            value={(aiConfig.max_tokens as number) ?? 4096}
            onChange={(e) => updateAiConfig('max_tokens', parseInt(e.target.value))}
            className={`w-full px-4 py-2.5 ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} focus:outline-none focus:border-amber-500/50`}
          />
        </div>
        <div>
          <label className={`block text-sm font-medium text-slate-300 mb-2`}>Timeout (seconds)</label>
          <input
            type="number"
            value={(aiConfig.timeout as number) ?? 60}
            onChange={(e) => updateAiConfig('timeout', parseInt(e.target.value))}
            className={`w-full px-4 py-2.5 ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} focus:outline-none focus:border-amber-500/50`}
          />
        </div>
      </div>

      <div>
        <label className={`block text-sm font-medium text-slate-300 mb-2`}>Max Input Events</label>
        <input
          type="number"
          value={(aiConfig.max_input_events as number) ?? 1000}
          onChange={(e) => updateAiConfig('max_input_events', parseInt(e.target.value))}
          className={`w-full px-4 py-2.5 ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} focus:outline-none focus:border-amber-500/50`}
        />
      </div>
    </div>
  );
}

// Friendly labels for secret keys
const SECRET_KEY_LABELS: Record<string, { label: string; description: string; placeholder: string }> = {
  'CTICHECKUP_ABUSEIPDB_API_KEY': {
    label: 'AbuseIPDB API Key',
    description: 'Required for IP reputation lookups',
    placeholder: 'Enter AbuseIPDB API key...',
  },
  'CTICHECKUP_IPINFO_TOKEN': {
    label: 'IPInfo Token',
    description: 'Required for domain lookups and cloud attribution',
    placeholder: 'Enter IPInfo token...',
  },
  'CTICHECKUP_IPINFO_REFERRER': {
    label: 'IPInfo Referrer',
    description: 'Required if IPInfo "Limit Referring Domains" is enabled',
    placeholder: 'https://yourdomain.com',
  },
  'CTICHECKUP_VIRUSTOTAL_API_KEY': {
    label: 'VirusTotal API Key',
    description: 'For hash, file, and URL reputation lookups',
    placeholder: 'Enter VirusTotal API key...',
  },
  'CTICHECKUP_AI_OPENAI_API_KEY': {
    label: 'OpenAI API Key',
    description: 'For AI-powered CloudTrail analysis',
    placeholder: 'sk-...',
  },
};

// Group keys by category for organized display
const SECRET_KEY_GROUPS = [
  {
    title: 'Threat Intelligence',
    description: 'API keys for IP, domain, and hash reputation lookups',
    keys: [
      'CTICHECKUP_ABUSEIPDB_API_KEY',
      'CTICHECKUP_IPINFO_TOKEN',
      'CTICHECKUP_IPINFO_REFERRER',
      'CTICHECKUP_VIRUSTOTAL_API_KEY',
    ],
  },
  {
    title: 'AI / LLM',
    description: 'API keys for AI-powered analysis features',
    keys: [
      'CTICHECKUP_AI_OPENAI_API_KEY',
    ],
  },
];

function APIKeysTab() {
  const { data: secretsStatus, refetch: refetchSecrets, setData: setSecretsStatus } = useApi(() => api.getSecretsStatus(), []);
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [keyInput, setKeyInput] = useState('');
  const [showValue, setShowValue] = useState(false);
  const [saving, setSaving] = useState(false);

  const handleSaveKey = async (keyName: string) => {
    if (!keyInput) return;
    setSaving(true);
    try {
      const res = await api.setSecret(keyName, keyInput);
      setKeyInput('');
      setEditingKey(null);
      setShowValue(false);
      if (res.secrets != null && res.envPath != null) {
        setSecretsStatus({ envPath: res.envPath, projectEnvPath: res.projectEnvPath, userEnvPath: res.userEnvPath, secrets: res.secrets });
      } else {
        await refetchSecrets();
      }
    } catch (err) {
      console.error('Failed to save key:', err);
    } finally {
      setSaving(false);
    }
  };

  const [deleting, setDeleting] = useState<string | null>(null);

  const handleDeleteKey = async (keyName: string) => {
    setDeleting(keyName);
    try {
      await api.deleteSecret(keyName);
      await refetchSecrets();
    } catch (err) {
      console.error('Failed to delete key:', err);
      alert(`Failed to delete key: ${err}`);
    } finally {
      setDeleting(null);
    }
  };

  const renderKeyRow = (keyName: string) => {
    const status = secretsStatus?.secrets[keyName];
    const meta = SECRET_KEY_LABELS[keyName] || {
      label: keyName.replace('CTICHECKUP_', '').replace(/_/g, ' '),
      description: '',
      placeholder: 'Enter value...',
    };
    const isEditing = editingKey === keyName;
    const isDeleting = deleting === keyName;
    const sourceLabel = status?.source === 'project' ? '(project .env)' 
                      : status?.source === 'user' ? '(~/.cti-checkup/.env)' 
                      : status?.source === 'env' ? '(shell env)' 
                      : '';

    return (
      <div key={keyName} className={`p-4 rounded-lg border ${status?.configured ? 'bg-green-500/5 border-green-500/20' : `${TW_COLORS.bgSurface} ${TW_COLORS.borderDefault}`}`}>
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-slate-300">{meta.label}</p>
            <p className={`text-xs ${TW_COLORS.textDisabled} mt-0.5`}>{meta.description}</p>
          </div>
          {status?.configured && !isEditing && (
            <div className="flex items-center gap-2 shrink-0">
              <CheckCircle className="w-4 h-4 text-green-400" />
              <span className={`text-xs ${TW_COLORS.textDisabled}`}>{status.masked}</span>
              {sourceLabel && (
                <span className={`text-xs ${TW_COLORS.textDisabled} italic`}>{sourceLabel}</span>
              )}
            </div>
          )}
        </div>

        {isEditing ? (
          <div className="mt-3 space-y-3">
            <div className="relative">
              <input
                type={showValue ? 'text' : 'password'}
                value={keyInput}
                onChange={(e) => setKeyInput(e.target.value)}
                placeholder={meta.placeholder}
                className={`w-full px-4 py-2.5 pr-10 ${TW_COLORS.bgElevated} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} focus:outline-none focus:border-amber-500/50`}
                autoFocus
              />
              <button
                onClick={() => setShowValue(!showValue)}
                className={`absolute right-3 top-1/2 -translate-y-1/2 ${TW_COLORS.textDisabled} hover:text-slate-400`}
              >
                {showValue ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleSaveKey(keyName)}
                disabled={!keyInput || saving}
                className="px-4 py-2 bg-amber-500 hover:bg-amber-600 disabled:opacity-50 text-slate-900 text-sm font-medium rounded-lg transition-colors"
              >
                {saving ? 'Saving...' : actions.save}
              </button>
              <button
                onClick={() => {
                  setEditingKey(null);
                  setKeyInput('');
                  setShowValue(false);
                }}
                className={`px-4 py-2 ${TW_COLORS.bgElevated} text-slate-300 text-sm font-medium rounded-lg hover:bg-[#1a2233] transition-colors`}
              >
                {actions.cancel}
              </button>
            </div>
          </div>
        ) : (
          <div className="mt-3 flex items-center gap-2">
            {status?.configured ? (
              <>
                <button
                  onClick={() => {
                    setEditingKey(keyName);
                    setKeyInput('');
                  }}
                  disabled={isDeleting}
                  className={`px-3 py-1.5 ${TW_COLORS.bgElevated} text-slate-300 text-xs font-medium rounded-lg hover:bg-[#1a2233] transition-colors disabled:opacity-50`}
                >
                  Update
                </button>
                <button
                  onClick={() => handleDeleteKey(keyName)}
                  disabled={isDeleting}
                  className="px-3 py-1.5 text-red-400 hover:text-red-300 text-xs font-medium transition-colors disabled:opacity-50"
                >
                  {isDeleting ? 'Removing...' : 'Remove'}
                </button>
              </>
            ) : (
              <button
                onClick={() => {
                  setEditingKey(keyName);
                  setKeyInput('');
                }}
                className="px-3 py-1.5 bg-amber-500/10 text-amber-400 text-xs font-medium rounded-lg hover:bg-amber-500/20 transition-colors"
              >
                Configure
              </button>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{settingsStrings.apikeys.title}</h3>
        <p className={`text-sm ${TW_COLORS.textDisabled} mb-2`}>{settingsStrings.apikeys.description}</p>
        <p className={`text-xs ${TW_COLORS.textDisabled}`}>
          {settingsStrings.apikeys.storedIn} <code className="px-1.5 py-0.5 bg-slate-700/50 rounded text-amber-400/80">{secretsStatus?.projectEnvPath ?? secretsStatus?.envPath ?? 'project .env'}</code>
        </p>
      </div>

      {SECRET_KEY_GROUPS.map((group) => (
        <div key={group.title}>
          <div className="mb-3">
            <h4 className="text-sm font-medium text-slate-300">{group.title}</h4>
            <p className={`text-xs ${TW_COLORS.textDisabled}`}>{group.description}</p>
          </div>
          <div className="space-y-3">
            {group.keys.map(renderKeyRow)}
          </div>
        </div>
      ))}
    </div>
  );
}

function ExportTab({ yamlConfig, setYamlConfig }: { 
  yamlConfig: Record<string, unknown>;
  setYamlConfig: (c: Record<string, unknown>) => void;
}) {
  const exportConfig = (yamlConfig.export || {}) as Record<string, unknown>;
  const enabledFormats = (exportConfig.formats || []) as string[];

  const updateExportConfig = (key: string, value: unknown) => {
    setYamlConfig({
      ...yamlConfig,
      export: { ...exportConfig, [key]: value }
    });
  };

  const toggleFormat = (format: string) => {
    const newFormats = enabledFormats.includes(format)
      ? enabledFormats.filter(f => f !== format)
      : [...enabledFormats, format];
    updateExportConfig('formats', newFormats);
  };

  const formats = [
    { id: 'sigma', label: 'Sigma', description: 'Generic SIEM detection rules' },
    { id: 'kql', label: 'KQL', description: 'Azure Sentinel queries' },
    { id: 'splunk', label: 'Splunk', description: 'Splunk SPL queries' },
    { id: 'cloudwatch', label: 'CloudWatch', description: 'AWS CloudWatch Logs Insights' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h3 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{settingsStrings.export.title}</h3>
        <p className={`text-sm ${TW_COLORS.textDisabled} mb-6`}>Configure detection rule export formats</p>
      </div>

      {/* Enable/Disable */}
      <div className={`flex items-center justify-between p-4 ${TW_COLORS.bgSurface} rounded-lg border ${TW_COLORS.borderDefault}`}>
        <div>
          <p className="text-sm font-medium text-slate-300">Enable Detection Export</p>
          <p className={`text-xs ${TW_COLORS.textDisabled}`}>Generate detection rules from findings</p>
        </div>
        <label className="relative inline-flex items-center cursor-pointer">
          <input 
            type="checkbox" 
            checked={exportConfig.enabled as boolean ?? true}
            onChange={(e) => updateExportConfig('enabled', e.target.checked)}
            className="sr-only peer" 
          />
          <div className={`w-11 h-6 ${TW_COLORS.bgSurface} peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-slate-400 after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-amber-500 peer-checked:after:bg-white`}></div>
        </label>
      </div>

      {/* Formats */}
      <div>
        <label className={`block text-sm font-medium text-slate-300 mb-2`}>{settingsStrings.export.enabledFormats}</label>
        <div className="space-y-2">
          {formats.map(format => (
            <label key={format.id} className={`flex items-center justify-between p-3 ${TW_COLORS.bgSurface} rounded-lg border ${TW_COLORS.borderDefault} cursor-pointer ${TW_COLORS.borderHover}`}>
              <div>
                <span className="text-sm text-slate-300">{format.label}</span>
                <p className={`text-xs ${TW_COLORS.textDisabled}`}>{format.description}</p>
              </div>
              <input
                type="checkbox"
                checked={enabledFormats.includes(format.id)}
                onChange={() => toggleFormat(format.id)}
                className="w-4 h-4 rounded border-slate-600 text-amber-500 focus:ring-amber-500/20"
              />
            </label>
          ))}
        </div>
        <p className={`text-xs ${TW_COLORS.textDisabled} mt-2`}>{settingsStrings.export.formatHint}</p>
      </div>

      {/* Templates Directory */}
      <div>
        <label className={`block text-sm font-medium text-slate-300 mb-2`}>Templates Directory</label>
        <input
          type="text"
          value={(exportConfig.templates_dir as string) || './templates'}
          onChange={(e) => updateExportConfig('templates_dir', e.target.value)}
          className={`w-full px-4 py-2.5 ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} focus:outline-none focus:border-amber-500/50`}
        />
      </div>
    </div>
  );
}

function PathsTab({ uiConfig, setUIConfig }: { 
  uiConfig: api.UIConfig; 
  setUIConfig: (c: api.UIConfig) => void;
}) {
  return (
    <div className="space-y-6">
      <div>
        <h3 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{settingsStrings.paths.title}</h3>
        <p className={`text-sm ${TW_COLORS.textDisabled} mb-6`}>Configure file paths (stored in ui_config.json)</p>
      </div>

      <div className="space-y-4">
        <div>
          <label className={`block text-sm font-medium text-slate-300 mb-2`}>{settingsStrings.paths.configFile}</label>
          <input
            type="text"
            value={uiConfig.configPath}
            onChange={(e) => setUIConfig({ ...uiConfig, configPath: e.target.value })}
            className={`w-full px-4 py-2.5 ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} font-mono focus:outline-none focus:border-amber-500/50`}
          />
          <p className={`text-xs ${TW_COLORS.textDisabled} mt-1`}>{settingsStrings.paths.configFileHint}</p>
        </div>

        <div>
          <label className={`block text-sm font-medium text-slate-300 mb-2`}>{settingsStrings.paths.runsDirectory}</label>
          <input
            type="text"
            value={uiConfig.runsDirectory}
            onChange={(e) => setUIConfig({ ...uiConfig, runsDirectory: e.target.value })}
            className={`w-full px-4 py-2.5 ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} font-mono focus:outline-none focus:border-amber-500/50`}
          />
          <p className={`text-xs ${TW_COLORS.textDisabled} mt-1`}>{settingsStrings.paths.runsDirectoryHint}</p>
        </div>
      </div>
    </div>
  );
}

function AdvancedTab({ yamlRaw, setYamlRaw }: { 
  yamlRaw: string;
  setYamlRaw: (s: string) => void;
}) {
  const [editMode, setEditMode] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleValidate = async () => {
    const result = await api.validateYAML(yamlRaw);
    if (result.valid) {
      setValidationError(null);
    } else {
      setValidationError(result.error || 'Invalid YAML');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-1`}>{settingsStrings.advanced.title}</h3>
          <p className={`text-sm ${TW_COLORS.textDisabled}`}>{settingsStrings.advanced.yamlEditorHint}</p>
        </div>
        <div className="flex items-center gap-2">
          {!editMode ? (
            <button
              onClick={() => setEditMode(true)}
              className="px-4 py-2 bg-yellow-500/10 text-yellow-400 rounded-lg text-sm font-medium hover:bg-yellow-500/20 transition-colors"
            >
              Enable Edit Mode
            </button>
          ) : (
            <>
              <button
                onClick={handleValidate}
                className={`px-4 py-2 ${TW_COLORS.bgElevated} text-slate-300 rounded-lg text-sm font-medium hover:bg-[#1a2233] transition-colors`}
              >
                {actions.validate}
              </button>
              <button
                onClick={() => {
                  setEditMode(false);
                  setValidationError(null);
                }}
                className={`px-4 py-2 ${TW_COLORS.bgElevated} text-slate-300 rounded-lg text-sm font-medium hover:bg-[#1a2233] transition-colors`}
              >
                {actions.cancel}
              </button>
            </>
          )}
        </div>
      </div>

      {editMode && (
        <div className="p-4 bg-yellow-500/5 border border-yellow-500/20 rounded-lg">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-yellow-400" />
            <span className="text-sm text-yellow-400">
              Warning: Direct YAML editing can break your configuration. Make sure you know what you're doing.
            </span>
          </div>
        </div>
      )}

      {validationError && (
        <div className="p-4 bg-red-500/5 border border-red-500/20 rounded-lg">
          <span className="text-sm text-red-400">{validationError}</span>
        </div>
      )}

      {!validationError && editMode && (
        <div className="p-4 bg-green-500/5 border border-green-500/20 rounded-lg">
          <span className="text-sm text-green-400">{settingsStrings.advanced.validYaml}</span>
        </div>
      )}

      <div className="relative">
        <textarea
          value={yamlRaw}
          onChange={(e) => setYamlRaw(e.target.value)}
          readOnly={!editMode}
          className={`w-full h-96 px-4 py-3 ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-lg text-sm ${TW_COLORS.textSecondary} font-mono focus:outline-none ${editMode ? 'focus:border-amber-500/50' : ''} resize-none`}
          spellCheck={false}
        />
      </div>
    </div>
  );
}

// ============ Main Settings Component ============

export function Settings() {
  const [activeTab, setActiveTab] = useState<TabId>('general');
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');

  // Load UI config
  const { data: uiConfigData, loading: uiLoading } = useApi(() => api.getUIConfig(), []);
  const [uiConfig, setUIConfig] = useState<api.UIConfig | null>(null);

  // Load YAML config
  const { data: yamlData, refetch: refetchYaml } = useApi(
    () => api.getYAMLConfig(uiConfig?.configPath),
    [uiConfig?.configPath]
  );
  const [yamlConfig, setYamlConfig] = useState<Record<string, unknown>>({});
  const [yamlRaw, setYamlRaw] = useState('');

  // Update local state when data loads
  useEffect(() => {
    if (uiConfigData) setUIConfig(uiConfigData);
  }, [uiConfigData]);

  useEffect(() => {
    if (yamlData) {
      setYamlConfig(yamlData.content);
      setYamlRaw(yamlData.raw);
    }
  }, [yamlData]);

  const handleSave = async () => {
    if (!uiConfig) return;
    
    setSaveStatus('saving');
    try {
      // Save UI config
      await api.saveUIConfig(uiConfig);
      
      // Save YAML config
      if (uiConfig.configPath) {
        await api.saveYAMLConfig(uiConfig.configPath, yamlConfig);
      }
      
      setSaveStatus('saved');
      setTimeout(() => setSaveStatus('idle'), 2000);
    } catch (err) {
      console.error('Save failed:', err);
      setSaveStatus('error');
    }
  };

  if (uiLoading || !uiConfig) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className={`w-6 h-6 ${TW_COLORS.textAccent} animate-spin`} />
      </div>
    );
  }

  return (
    <div className="flex gap-6">
      {/* Tabs Sidebar */}
      <div className="w-56 shrink-0">
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-2 sticky top-6`}>
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? `${TW_COLORS.bgAccent} ${TW_COLORS.textAccent}`
                  : `${TW_COLORS.textMuted} hover:bg-[#1a2233] hover:text-slate-300`
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1">
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
          {activeTab === 'general' && <GeneralTab uiConfig={uiConfig} setUIConfig={setUIConfig} />}
          {activeTab === 'aws' && <AWSTab uiConfig={uiConfig} setUIConfig={setUIConfig} yamlConfig={yamlConfig} setYamlConfig={setYamlConfig} />}
          {activeTab === 'ai' && <AITab yamlConfig={yamlConfig} setYamlConfig={setYamlConfig} />}
          {activeTab === 'apikeys' && <APIKeysTab />}
          {activeTab === 'export' && <ExportTab yamlConfig={yamlConfig} setYamlConfig={setYamlConfig} />}
          {activeTab === 'paths' && <PathsTab uiConfig={uiConfig} setUIConfig={setUIConfig} />}
          {activeTab === 'advanced' && <AdvancedTab yamlRaw={yamlRaw} setYamlRaw={setYamlRaw} />}
        </div>

        {/* Save Button */}
        <div className="flex items-center justify-end gap-4 mt-6">
          {saveStatus === 'saved' && (
            <span className="text-sm text-green-400 flex items-center gap-1">
              <CheckCircle className="w-4 h-4" />
              Saved
            </span>
          )}
          {saveStatus === 'error' && (
            <span className="text-sm text-red-400">Save failed</span>
          )}
          <button
            onClick={handleSave}
            disabled={saveStatus === 'saving'}
            className="flex items-center gap-2 px-6 py-2.5 bg-amber-500 hover:bg-amber-600 disabled:opacity-50 text-slate-900 font-medium rounded-lg transition-colors"
          >
            {saveStatus === 'saving' ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {actions.save} Changes
          </button>
        </div>
      </div>
    </div>
  );
}
