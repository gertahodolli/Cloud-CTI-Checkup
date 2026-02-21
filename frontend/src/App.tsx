import { useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppProvider } from './context/AppContext';
import { Layout } from './components/layout/Layout';
import { Dashboard } from './pages/Dashboard';
import { Findings } from './pages/Findings';
import { Assets } from './pages/Assets';
import { Compliance } from './pages/Compliance';
import { AIInsights } from './pages/AIInsights';
import { Intel } from './pages/Intel';
import { Indicators } from './pages/Indicators';
import { CloudTrail } from './pages/CloudTrail';
import { Alerts } from './pages/Alerts';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';
import { APP_TITLE } from './constants/app';

function App() {
  // Set document title from constants
  useEffect(() => {
    document.title = APP_TITLE;
  }, []);
  return (
    <AppProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="findings" element={<Findings />} />
            <Route path="assets" element={<Assets />} />
            <Route path="compliance" element={<Compliance />} />
            <Route path="ai-insights" element={<AIInsights />} />
            <Route path="cloudtrail" element={<CloudTrail />} />
            <Route path="intel" element={<Intel />} />
            <Route path="indicators" element={<Indicators />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="reports" element={<Reports />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AppProvider>
  );
}

export default App;
