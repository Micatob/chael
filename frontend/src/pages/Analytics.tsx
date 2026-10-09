import { useEffect, useState } from 'react';
import { useLogStore, useIncidentStore } from '../stores';
import { StatCard } from '../components/ui';
import { AlertTriangle, Network, FileText } from 'lucide-react';
import * as echarts from 'echarts/core';
import { LineChart as ELineChart, BarChart as EBarChart } from 'echarts/charts';
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import ReactECharts from 'echarts-for-react';
import { apiService } from '../services/api';
import { LogSource } from '../types';

echarts.use([ELineChart, EBarChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer]);

export function Analytics() {
  const { logs } = useLogStore();
  const { incidents } = useIncidentStore();
  const [lineChartOption, setLineChartOption] = useState<any>(null);
  const [barChartOption, setBarChartOption] = useState<any>(null);

  useEffect(() => {
    const hourlyData = logs.reduce((acc: Record<string, number>, log) => {
      const hour = new Date(log.timestamp).toISOString().slice(0, 13);
      acc[hour] = (acc[hour] || 0) + 1;
      return acc;
    }, {});

    const hours = Object.keys(hourlyData).sort();
    const values = hours.map((h) => hourlyData[h]);

    const lineOption = {
      tooltip: { trigger: 'axis' },
      grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
      xAxis: {
        type: 'category',
        data: hours.map((h) => h.slice(11) + ':00'),
        axisLine: { lineStyle: { color: '#4b5563' } },
        axisLabel: { color: '#9ca3af' },
      },
      yAxis: {
        type: 'value',
        axisLine: { lineStyle: { color: '#4b5563' } },
        axisLabel: { color: '#9ca3af' },
        splitLine: { lineStyle: { color: '#374151' } },
      },
      series: [
        {
          data: values,
          type: 'line',
          smooth: true,
          itemStyle: { color: '#10b981' },
          areaStyle: {
            color: {
              type: 'linear',
              x: 0, y: 0, x2: 0, y2: 1,
              colorStops: [
                { offset: 0, color: 'rgba(34, 197, 94, 0.2)' },
                { offset: 1, color: 'rgba(34, 197, 94, 0.02)' },
              ],
            },
          },
        },
      ],
    };

    const sourceData = logs.reduce((acc: Record<string, number>, log) => {
      acc[log.source] = (acc[log.source] || 0) + 1;
      return acc;
    }, {});

    const barOption = {
      tooltip: { trigger: 'axis' },
      grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
      xAxis: {
        type: 'category',
        data: Object.keys(sourceData),
        axisLine: { lineStyle: { color: '#4b5563' } },
        axisLabel: { color: '#9ca3af', rotate: 45 },
      },
      yAxis: {
        type: 'value',
        axisLine: { lineStyle: { color: '#4b5563' } },
        axisLabel: { color: '#9ca3af' },
        splitLine: { lineStyle: { color: '#374151' } },
      },
      series: [
        {
          data: Object.values(sourceData),
          type: 'bar',
          itemStyle: {
            color: (params: any) => {
              const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];
              return colors[params.dataIndex % colors.length];
            },
          },
        },
      ],
    };

    setLineChartOption(lineOption);
    setBarChartOption(barOption);
  }, [logs]);

  const [sources, setSources] = useState<LogSource[]>([]);
  const [sourcesLoading, setSourcesLoading] = useState(true);

  useEffect(() => {
    const fetchSources = async () => {
      try {
        const res = await apiService.getLogSources();
        setSources(res.data || []);
      } catch {
        setSources([]);
      } finally {
        setSourcesLoading(false);
      }
    };
    fetchSources();
    const interval = setInterval(fetchSources, 30000);
    return () => clearInterval(interval);
  }, []);

  const totalLogs = logs.length;
  const totalIncidents = incidents.length;
  const openIncidents = incidents.filter((i) => i.status === 'OPEN' || i.status === 'INVESTIGATING').length;
  const avgRiskScore = totalIncidents > 0
    ? Math.round(incidents.reduce((a, b) => a + b.risk_score, 0) / totalIncidents)
    : 0;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <StatCard
          title="Total Logs"
          value={totalLogs}
          icon={<FileText className="w-8 h-8" />}
        />
        <StatCard
          title="Total Incidents"
          value={totalIncidents}
          icon={<AlertTriangle className="w-8 h-8" />}
        />
        <StatCard
          title="Open Incidents"
          value={openIncidents}
          icon={<AlertTriangle className="w-8 h-8" />}
          trend={{ value: openIncidents > 5 ? 15 : -5, label: 'trend' }}
        />
        <StatCard
          title="Avg Risk Score"
          value={avgRiskScore}
          icon={<Network className="w-8 h-8" />}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '24px' }}>
          <h3 className="text-lg font-semibold mb-4">Ingestion Trend</h3>
          {lineChartOption && <ReactECharts option={lineChartOption} style={{ height: '300px' }} />}
        </div>

        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '24px' }}>
          <h3 className="text-lg font-semibold mb-4">Logs by Source</h3>
          {barChartOption && <ReactECharts option={barChartOption} style={{ height: '300px' }} />}
        </div>
      </div>

      <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '4px', padding: '24px' }}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">Log Sources / Heartbeat</h3>
          {sourcesLoading && <span className="text-xs" style={{ color: '#6b7280' }}>Refreshing...</span>}
          {!sourcesLoading && <span className="text-xs" style={{ color: '#6b7280' }}>{sources.length} source(s)</span>}
        </div>
        {sources.length === 0 ? (
          <div className="text-sm italic p-4 text-center border border-dashed rounded-lg" style={{ color: '#6b7280', borderColor: 'rgba(75,85,99,0.2)' }}>
            No log sources reported yet. Deploy an agent or send a heartbeat via <code style={{ color: '#60a5fa' }}>POST /api/logs/heartbeat</code>.
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {sources.map((src) => {
              const isOnline = src.status === 'online';
              const timeAgo = Math.floor((Date.now() - new Date(src.timestamp).getTime()) / 1000);
              const isStale = timeAgo > 120;
              return (
                <div key={src.hostname} style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,85,99,0.2)', borderRadius: '8px', padding: '12px' }}>
                  <div className="flex items-center gap-2 mb-1">
                    <div className={`w-2 h-2 rounded-full ${isOnline && !isStale ? 'bg-green-500' : isStale ? 'bg-yellow-500' : 'bg-red-500'}`} />
                    <p className="text-sm font-semibold truncate" style={{ color: '#d1d5db' }}>{src.hostname}</p>
                  </div>
                  <p className="text-xs" style={{ color: '#6b7280' }}>{src.source_type}</p>
                  <p className="text-[10px] mt-1" style={{ color: '#6b7280' }}>
                    {isStale ? `${timeAgo}s ago (stale)` : `${timeAgo}s ago`}
                  </p>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
