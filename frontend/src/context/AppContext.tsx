import React, { createContext, useContext, useState, useEffect, useRef, ReactNode } from 'react';
import * as api from '../api/client';

export interface CloudTrailUpload {
  fileName: string;
  fileSize: number;
  fileContent: string;
  mode: 'baseline' | 'llm';
}

interface AppState {
  // UI Config
  uiConfig: api.UIConfig | null;
  
  // Connection status
  serverConnected: boolean;
  
  // Current run data
  runs: api.Run[];
  runsDir: string | null;
  selectedRunId: string | null;
  
  // Global search (TopBar → Findings, etc.)
  searchQuery: string;
  
  // CloudTrail upload (persists across tab navigation)
  cloudtrailUpload: CloudTrailUpload | null;
  
  // Loading states
  loading: boolean;
}

interface AppContextValue extends AppState {
  refetchConfig: () => void;
  refetchRuns: () => void;
  selectRun: (id: string | null) => void;
  setSearchQuery: (query: string) => void;
  setUIConfig: (config: api.UIConfig) => void;
  setCloudTrailUpload: (upload: CloudTrailUpload | null) => void;
}

const AppContext = createContext<AppContextValue | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [uiConfig, setUIConfigState] = useState<api.UIConfig | null>(null);
  const [serverConnected, setServerConnected] = useState(false);
  const [runs, setRuns] = useState<api.Run[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [cloudtrailUpload, setCloudTrailUpload] = useState<CloudTrailUpload | null>(null);
  const [loading, setLoading] = useState(true);

  // Refs to avoid stale closures in interval/callbacks (fixes selection reset on refetch)
  const selectedRunIdRef = useRef<string | null>(null);
  const serverConnectedRef = useRef(false);
  selectedRunIdRef.current = selectedRunId;
  serverConnectedRef.current = serverConnected;

  const checkServer = async () => {
    try {
      await api.checkHealth();
      setServerConnected(true);
      return true;
    } catch {
      setServerConnected(false);
      return false;
    }
  };

  const fetchConfig = async () => {
    try {
      const config = await api.getUIConfig();
      setUIConfigState(config);
    } catch (err) {
      console.error('Failed to fetch UI config:', err);
    }
  };

  const fetchRuns = async () => {
    try {
      const data = await api.getRuns();
      setRuns(data.runs);
      
      // Auto-select the latest run only if none selected (use ref to avoid stale closure)
      if (!selectedRunIdRef.current && data.runs.length > 0) {
        setSelectedRunId(data.runs[0].id);
      }
    } catch (err) {
      console.error('Failed to fetch runs:', err);
    }
  };

  useEffect(() => {
    const init = async () => {
      setLoading(true);
      const connected = await checkServer();
      if (connected) {
        await fetchConfig();
        await fetchRuns();
      }
      setLoading(false);
    };
    
    init();
    
    // Poll for server connection (use ref to avoid stale closure - wasConnected was always false)
    const interval = setInterval(async () => {
      const wasConnected = serverConnectedRef.current;
      const isConnected = await checkServer();
      
      // Refetch data only when connection is restored (not every poll)
      if (!wasConnected && isConnected) {
        await fetchConfig();
        await fetchRuns();
      }
    }, 5000);
    
    return () => clearInterval(interval);
  }, []);

  const value: AppContextValue = {
    uiConfig,
    serverConnected,
    runs,
    selectedRunId,
    searchQuery,
    cloudtrailUpload,
    loading,
    refetchConfig: fetchConfig,
    refetchRuns: fetchRuns,
    selectRun: setSelectedRunId,
    setSearchQuery,
    setUIConfig: setUIConfigState,
    setCloudTrailUpload,
  };

  return (
    <AppContext.Provider value={value}>
      {children}
    </AppContext.Provider>
  );
}

export function useApp(): AppContextValue {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within AppProvider');
  }
  return context;
}
