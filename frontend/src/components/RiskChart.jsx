import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Box, Typography } from '@mui/material';

const RiskChart = ({ incidents }) => {
  const chartData = incidents
    .slice(0, 30)
    .map((inc, index) => ({
      time: new Date(inc.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      risk: +(inc.playbook_summary?.risk || 0).toFixed(3),
      index,
    }))
    .reverse();

  if (chartData.length === 0) {
    return (
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
        <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.3)' }}>
          No data yet. Click "Simulate Traffic" to generate events.
        </Typography>
      </Box>
    );
  }

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      const risk = payload[0].value;
      const color = risk > 0.7 ? '#ff4d6d' : risk > 0.4 ? '#ffb703' : '#80ed99';
      return (
        <Box
          sx={{
            bgcolor: 'rgba(16,16,32,0.95)',
            backdropFilter: 'blur(12px)',
            border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: '8px',
            p: 1.5,
          }}
        >
          <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.5)' }}>
            {label}
          </Typography>
          <Typography variant="body2" sx={{ color, fontWeight: 700 }}>
            Risk: {(risk * 100).toFixed(1)}%
          </Typography>
        </Box>
      );
    }
    return null;
  };

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#f72585" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#f72585" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
        <XAxis dataKey="time" stroke="rgba(255,255,255,0.15)" tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10 }} />
        <YAxis
          stroke="rgba(255,255,255,0.15)"
          tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10 }}
          domain={[0, 1]}
          tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
        />
        <Tooltip content={<CustomTooltip />} />
        <Area type="monotone" dataKey="risk" stroke="#f72585" strokeWidth={2} fill="url(#riskGrad)" dot={false} activeDot={{ r: 4, fill: '#f72585' }} />
      </AreaChart>
    </ResponsiveContainer>
  );
};

export default RiskChart;
