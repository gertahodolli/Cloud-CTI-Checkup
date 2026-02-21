import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, TooltipProps } from 'recharts';
import type { TrendDataPoint } from '../../types';

interface FindingsTrendChartProps {
  data: TrendDataPoint[];
}

function CustomTooltip({ active, payload, label }: TooltipProps<number, string>) {
  if (active && payload && payload.length) {
    return (
      <div className="bg-[#1a2233] border border-[#334155] rounded-lg p-3 shadow-xl">
        <p className="text-xs text-slate-400 mb-2">{label}</p>
        <div className="space-y-1">
          <div className="flex items-center justify-between gap-4">
            <span className="text-xs text-slate-300">Total</span>
            <span className="text-sm font-semibold text-amber-400">{payload[0]?.value}</span>
          </div>
          {payload.slice(1).map((entry, index) => (
            <div key={index} className="flex items-center justify-between gap-4">
              <span className="text-xs text-slate-400">{entry.name}</span>
              <span className="text-xs font-medium" style={{ color: entry.color }}>{entry.value}</span>
            </div>
          ))}
        </div>
      </div>
    );
  }
  return null;
}

export function FindingsTrendChart({ data }: FindingsTrendChartProps) {
  // Format date for display
  const formattedData = data.map(d => ({
    ...d,
    displayDate: new Date(d.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
  }));

  return (
    <div className="bg-[#121826] rounded-xl p-6 border border-[#1E293B]">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-lg font-semibold text-slate-200">Findings Trend</h3>
          <p className="text-sm text-slate-500">Last 30 days</p>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-amber-400" />
            <span className="text-slate-400">Total</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-red-400" />
            <span className="text-slate-400">Critical</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-orange-400" />
            <span className="text-slate-400">High</span>
          </div>
        </div>
      </div>

      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={formattedData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
            <XAxis 
              dataKey="displayDate" 
              axisLine={false}
              tickLine={false}
              tick={{ fill: '#64748B', fontSize: 11 }}
              dy={10}
            />
            <YAxis 
              axisLine={false}
              tickLine={false}
              tick={{ fill: '#64748B', fontSize: 11 }}
              dx={-10}
            />
            <Tooltip content={<CustomTooltip />} />
            <Line 
              type="monotone" 
              dataKey="findings" 
              name="Total"
              stroke="#F59E0B" 
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4, fill: '#F59E0B', stroke: '#0E1117', strokeWidth: 2 }}
            />
            <Line 
              type="monotone" 
              dataKey="critical" 
              name="Critical"
              stroke="#EF4444" 
              strokeWidth={1.5}
              strokeDasharray="4 4"
              dot={false}
              activeDot={{ r: 3, fill: '#EF4444', stroke: '#0E1117', strokeWidth: 2 }}
            />
            <Line 
              type="monotone" 
              dataKey="high" 
              name="High"
              stroke="#F97316" 
              strokeWidth={1.5}
              strokeDasharray="4 4"
              dot={false}
              activeDot={{ r: 3, fill: '#F97316', stroke: '#0E1117', strokeWidth: 2 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
