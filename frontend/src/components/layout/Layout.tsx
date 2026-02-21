import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { useApp } from '../../context/AppContext';
import { RefreshCw, WifiOff } from 'lucide-react';
import { loading, server } from '../../constants/strings';
import { TW_COLORS } from '../../constants/theme';

export function Layout() {
  const { loading: isLoading, serverConnected } = useApp();

  if (isLoading) {
    return (
      <div className={`min-h-screen ${TW_COLORS.bgBase} flex items-center justify-center`}>
        <div className="text-center">
          <RefreshCw className={`w-8 h-8 ${TW_COLORS.textAccent} animate-spin mx-auto mb-4`} />
          <p className={TW_COLORS.textMuted}>{loading.default}</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`min-h-screen ${TW_COLORS.bgBase}`}>
      <Sidebar />
      <TopBar />
      <main className="ml-60 pt-16 min-h-screen">
        <div className="p-6">
          {!serverConnected && (
            <div className="mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-lg flex items-center gap-3">
              <WifiOff className="w-5 h-5 text-red-400" />
              <div>
                <p className="text-sm font-medium text-red-400">{server.notConnected}</p>
                <p className={`text-xs ${TW_COLORS.textDisabled}`}>
                  {server.notConnectedHint}
                </p>
              </div>
            </div>
          )}
          <Outlet />
        </div>
      </main>
    </div>
  );
}
