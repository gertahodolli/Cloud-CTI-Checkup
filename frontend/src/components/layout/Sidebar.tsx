import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Search, 
  Server, 
  Shield, 
  Bell, 
  FileText, 
  Settings,
  Sparkles,
  Wifi,
  WifiOff,
  Globe,
  Fingerprint,
  Cloud
} from 'lucide-react';
import { useApp } from '../../context/AppContext';
import { APP_NAME, APP_TAGLINE } from '../../constants/app';
import { nav } from '../../constants/strings';
import { TW_COLORS } from '../../constants/theme';

const navItems = [
  { id: 'dashboard', label: nav.dashboard, icon: LayoutDashboard, path: '/' },
  { id: 'findings', label: nav.findings, icon: Search, path: '/findings' },
  { id: 'assets', label: nav.assets, icon: Server, path: '/assets' },
  { id: 'compliance', label: nav.compliance, icon: Shield, path: '/compliance' },
  { id: 'ai-insights', label: nav.aiInsights, icon: Sparkles, path: '/ai-insights' },
  { id: 'cloudtrail', label: nav.cloudtrail, icon: Cloud, path: '/cloudtrail' },
  { id: 'intel', label: nav.intel, icon: Globe, path: '/intel' },
  { id: 'indicators', label: nav.indicators, icon: Fingerprint, path: '/indicators' },
  { id: 'alerts', label: nav.alerts, icon: Bell, path: '/alerts' },
  { id: 'reports', label: nav.reports, icon: FileText, path: '/reports' },
  { id: 'settings', label: nav.settings, icon: Settings, path: '/settings' },
];

export function Sidebar() {
  const { serverConnected, runs } = useApp();
  
  // Calculate alert count from latest run findings
  const latestRun = runs[0];
  const alertCount = latestRun?.summary 
    ? latestRun.summary.summary.critical + latestRun.summary.summary.high
    : 0;

  return (
    <aside className={`fixed left-0 top-0 h-full w-60 ${TW_COLORS.bgSurface} border-r ${TW_COLORS.borderDefault} flex flex-col z-50`}>
      {/* Logo */}
      <div className={`p-5 border-b ${TW_COLORS.borderDefault}`}>
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-amber-500 to-amber-600 flex items-center justify-center shadow-lg shadow-amber-500/20">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-white">{APP_NAME}</h1>
            <p className={TW_COLORS.textDisabled + ' text-xs'}>{APP_TAGLINE}</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.id}
            to={item.path}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 group relative ${
                isActive
                  ? 'bg-amber-500/10 text-amber-500 shadow-[0_0_20px_rgba(245,158,11,0.1)]'
                  : `${TW_COLORS.textMuted} hover:${TW_COLORS.textSecondary} hover:${TW_COLORS.bgElevated}`
              }`
            }
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-amber-500 rounded-r-full" />
                )}
                <item.icon className={`w-5 h-5 ${isActive ? 'text-amber-500' : `${TW_COLORS.textDisabled} group-hover:${TW_COLORS.textMuted}`}`} />
                <span className="text-sm font-medium">{item.label}</span>
                {item.id === 'alerts' && alertCount > 0 && (
                  <span className="ml-auto bg-red-500 text-white text-xs font-medium px-2 py-0.5 rounded-full min-w-[20px] text-center">
                    {alertCount}
                  </span>
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Server status */}
      <div className={`p-3 border-t ${TW_COLORS.borderDefault}`}>
        <div className="flex items-center gap-3 px-3 py-2.5 rounded-lg">
          {serverConnected ? (
            <>
              <Wifi className="w-4 h-4 text-green-400" />
              <span className="text-xs text-green-400">Server connected</span>
            </>
          ) : (
            <>
              <WifiOff className="w-4 h-4 text-red-400" />
              <span className="text-xs text-red-400">Server offline</span>
            </>
          )}
        </div>
      </div>
    </aside>
  );
}
