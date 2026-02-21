import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Server, Cloud, Database, Shield, ChevronRight, RefreshCw, AlertTriangle } from 'lucide-react';
import { useApp } from '../context/AppContext';
import * as api from '../api/client';
import type { Finding } from '../types';
import { assets as assetsStrings, empty } from '../constants/strings';
import { TW_COLORS } from '../constants/theme';

interface AssetCategory {
  name: string;
  service: string;
  count: number;
  icon: typeof Server;
  color: string;
  bgColor: string;
  findings: number;
}

const serviceConfig: Record<string, { name: string; icon: typeof Server; color: string; bgColor: string }> = {
  S3: { name: 'S3 Buckets', icon: Database, color: 'text-green-400', bgColor: 'bg-green-500/10' },
  IAM: { name: 'IAM Resources', icon: Shield, color: 'text-purple-400', bgColor: 'bg-purple-500/10' },
  EC2: { name: 'EC2 Resources', icon: Server, color: 'text-blue-400', bgColor: 'bg-blue-500/10' },
};

function categorizeFindings(findings: Finding[]): AssetCategory[] {
  const serviceMap = new Map<string, { resources: Set<string>; findingsCount: number }>();
  
  for (const finding of findings) {
    const service = finding.service.toUpperCase();
    const resourceId = finding.resource_id;
    
    if (!serviceMap.has(service)) {
      serviceMap.set(service, { resources: new Set(), findingsCount: 0 });
    }
    
    const data = serviceMap.get(service)!;
    data.resources.add(resourceId);
    data.findingsCount++;
  }
  
  return Array.from(serviceMap.entries()).map(([service, data]) => {
    const config = serviceConfig[service] || { 
      name: `${service} Resources`, 
      icon: Cloud, 
      color: TW_COLORS.textAccent, 
      bgColor: TW_COLORS.bgAccent 
    };
    
    return {
      name: config.name,
      service,
      count: data.resources.size,
      icon: config.icon,
      color: config.color,
      bgColor: config.bgColor,
      findings: data.findingsCount
    };
  }).sort((a, b) => b.findings - a.findings);
}

export function Assets() {
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

  const assetCategories = useMemo(() => categorizeFindings(findings), [findings]);
  
  const totalAssets = assetCategories.reduce((sum, cat) => sum + cat.count, 0);
  const totalFindings = assetCategories.reduce((sum, cat) => sum + cat.findings, 0);
  const uniqueRegions = new Set(findings.map(f => f.region).filter(Boolean)).size;

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
      <div>
        <h1 className={`text-2xl font-bold ${TW_COLORS.textPrimary}`}>{assetsStrings.title}</h1>
        <p className={`text-sm ${TW_COLORS.textDisabled} mt-1`}>
          {assetsStrings.subtitle(totalAssets, totalFindings)}
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-5`}>
          <p className={`text-sm ${TW_COLORS.textMuted} mb-1`}>{assetsStrings.resourcesWithFindings}</p>
          <p className={`text-3xl font-bold ${TW_COLORS.textPrimary}`}>{totalAssets}</p>
        </div>
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-5`}>
          <p className={`text-sm ${TW_COLORS.textMuted} mb-1`}>{assetsStrings.totalFindings}</p>
          <p className={`text-3xl font-bold ${TW_COLORS.textAccent}`}>{totalFindings}</p>
        </div>
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-5`}>
          <p className={`text-sm ${TW_COLORS.textMuted} mb-1`}>{assetsStrings.regions}</p>
          <p className={`text-3xl font-bold ${TW_COLORS.textPrimary}`}>{uniqueRegions || 'N/A'}</p>
        </div>
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-5`}>
          <p className={`text-sm ${TW_COLORS.textMuted} mb-1`}>{assetsStrings.services}</p>
          <p className={`text-3xl font-bold ${TW_COLORS.textPrimary}`}>{assetCategories.length}</p>
        </div>
      </div>

      {/* Asset Categories */}
      {assetCategories.length > 0 ? (
        <div className="grid grid-cols-3 gap-4">
          {assetCategories.map((category) => (
            <div
              key={category.service}
              role="button"
              tabIndex={0}
              onClick={() => navigate(`/findings?service=${encodeURIComponent(category.service.toLowerCase())}`)}
              onKeyDown={(e) => e.key === 'Enter' && navigate(`/findings?service=${encodeURIComponent(category.service.toLowerCase())}`)}
              className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-5 ${TW_COLORS.borderHover} transition-all cursor-pointer group`}
            >
              <div className="flex items-start justify-between mb-4">
                <div className={`w-10 h-10 rounded-lg ${category.bgColor} flex items-center justify-center`}>
                  <category.icon className={`w-5 h-5 ${category.color}`} />
                </div>
                <ChevronRight className={`w-5 h-5 ${TW_COLORS.textDisabled} opacity-0 group-hover:opacity-100 transition-opacity`} />
              </div>
              <h3 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-1`}>{category.name}</h3>
              <div className="flex items-center justify-between">
                <span className={`text-sm ${TW_COLORS.textDisabled}`}>{assetsStrings.resourcesLabel(category.count)}</span>
                {category.findings > 0 && (
                  <span className="text-xs px-2 py-0.5 bg-red-500/10 text-red-400 rounded-full">
                    {assetsStrings.findingsLabel(category.findings)}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-12 text-center`}>
          <Server className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <h3 className={`text-lg font-medium ${TW_COLORS.textSecondary} mb-2`}>{assetsStrings.noAssets}</h3>
          <p className={TW_COLORS.textDisabled}>
            {!selectedRunId 
              ? assetsStrings.selectRunHint
              : assetsStrings.noAssetsHint}
          </p>
        </div>
      )}

      {/* Findings by Region */}
      {findings.length > 0 && (
        <div className={`${TW_COLORS.bgElevated} rounded-xl border ${TW_COLORS.borderDefault} p-6`}>
          <h2 className={`text-lg font-semibold ${TW_COLORS.textSecondary} mb-4`}>{assetsStrings.findingsByRegion}</h2>
          <div className="flex flex-wrap gap-2">
            {Array.from(new Set(findings.map(f => f.region || 'Global'))).map(region => {
              const count = findings.filter(f => (f.region || 'Global') === region).length;
              return (
                <div 
                  key={region}
                  className={`px-4 py-2 ${TW_COLORS.bgSurface} border ${TW_COLORS.borderDefault} rounded-lg`}
                >
                  <span className="text-sm text-slate-300">{region}</span>
                  <span className={`text-xs ${TW_COLORS.textDisabled} ml-2`}>{assetsStrings.findingsLabel(count)}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
