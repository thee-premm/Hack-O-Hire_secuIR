import React, { useState, useEffect, useCallback } from 'react';
import { Grid, Paper, Typography, Box, Tab, Tabs, Button, CircularProgress } from '@mui/material';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import RefreshIcon from '@mui/icons-material/Refresh';
import MetricsCards from './MetricsCards';
import RiskChart from './RiskChart';
import IncidentTable from './IncidentTable';
import AlertCard from './AlertCard';
import PlaybookModal from './PlaybookModal';
import { getIncidents, getStats, simulateTraffic } from '../services/api';

const Dashboard = ({ stats, onStatsUpdate, realtimeIncident }) => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [tabValue, setTabValue] = useState(0);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [simulating, setSimulating] = useState(false);

  const loadIncidents = useCallback(async () => {
    try {
      const data = await getIncidents(50);
      setIncidents(data.incidents);
    } catch {
      // Backend may not be running yet
    }
  }, []);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  useEffect(() => {
    if (realtimeIncident) {
      loadIncidents();
      onStatsUpdate();
    }
  }, [realtimeIncident, loadIncidents, onStatsUpdate]);

  const handleSimulate = async () => {
    setSimulating(true);
    try {
      await simulateTraffic(15);
      await loadIncidents();
      await onStatsUpdate();
    } catch (err) {
      console.error('Simulation failed:', err);
    } finally {
      setSimulating(false);
    }
  };

  const handleRefresh = async () => {
    setLoading(true);
    await loadIncidents();
    await onStatsUpdate();
    setLoading(false);
  };

  const panelStyle = {
    p: 2.5,
    bgcolor: 'rgba(22,22,44,0.5)',
    backdropFilter: 'blur(12px)',
    border: '1px solid rgba(255,255,255,0.05)',
    borderRadius: '16px',
  };

  return (
    <Box>
      {/* Toolbar */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, color: 'rgba(255,255,255,0.9)' }}>
          Threat Intelligence Dashboard
        </Typography>
        <Box sx={{ display: 'flex', gap: 1.5 }}>
          <Button
            variant="outlined"
            size="small"
            startIcon={loading ? <CircularProgress size={14} /> : <RefreshIcon />}
            onClick={handleRefresh}
            disabled={loading}
            sx={{
              borderColor: 'rgba(255,255,255,0.1)',
              color: 'rgba(255,255,255,0.5)',
              borderRadius: '8px',
              textTransform: 'none',
              '&:hover': { borderColor: 'rgba(0,180,216,0.4)', color: '#00b4d8' },
            }}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            size="small"
            startIcon={simulating ? <CircularProgress size={14} color="inherit" /> : <PlayArrowIcon />}
            onClick={handleSimulate}
            disabled={simulating}
            sx={{
              background: 'linear-gradient(135deg, #00b4d8, #7209b7)',
              borderRadius: '8px',
              textTransform: 'none',
              fontWeight: 600,
              px: 2.5,
              boxShadow: '0 4px 20px rgba(0,180,216,0.25)',
              '&:hover': { boxShadow: '0 6px 30px rgba(0,180,216,0.4)' },
            }}
          >
            Simulate Traffic
          </Button>
        </Box>
      </Box>

      {/* Metrics */}
      <MetricsCards stats={stats} />

      {/* Charts Row */}
      <Grid container spacing={2.5} sx={{ mt: 1 }}>
        <Grid item xs={12} md={7}>
          <Paper sx={{ ...panelStyle, height: 340 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, color: 'rgba(255,255,255,0.6)', mb: 1, fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.6px' }}>
              Risk Trend Analysis
            </Typography>
            <Box sx={{ height: 'calc(100% - 30px)' }}>
              <RiskChart incidents={incidents} />
            </Box>
          </Paper>
        </Grid>
        <Grid item xs={12} md={5}>
          <Paper sx={{ ...panelStyle, height: 340 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, color: 'rgba(255,255,255,0.6)', mb: 1, fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.6px' }}>
              Recent Alerts
            </Typography>
            <Box sx={{ height: 'calc(100% - 30px)' }}>
              <AlertCard incidents={incidents.slice(-8).reverse()} />
            </Box>
          </Paper>
        </Grid>
      </Grid>

      {/* Incidents Table */}
      <Paper sx={{ ...panelStyle, mt: 2.5 }}>
        <Box sx={{ borderBottom: '1px solid rgba(255,255,255,0.06)', mb: 2 }}>
          <Tabs
            value={tabValue}
            onChange={(_, v) => setTabValue(v)}
            sx={{
              minHeight: 36,
              '& .MuiTab-root': {
                minHeight: 36,
                textTransform: 'none',
                fontSize: '0.8rem',
                fontWeight: 500,
                color: 'rgba(255,255,255,0.35)',
                '&.Mui-selected': { color: '#00b4d8' },
              },
              '& .MuiTabs-indicator': { bgcolor: '#00b4d8', height: 2 },
            }}
          >
            <Tab label="All Incidents" />
            <Tab label="Critical" />
            <Tab label="Medium" />
            <Tab label="Low" />
          </Tabs>
        </Box>
        <IncidentTable
          incidents={incidents}
          riskFilter={tabValue}
          onViewPlaybook={(inc) => setSelectedIncident(inc)}
        />
      </Paper>

      {/* Playbook Modal */}
      <PlaybookModal
        incident={selectedIncident}
        open={!!selectedIncident}
        onClose={() => setSelectedIncident(null)}
      />
    </Box>
  );
};

export default Dashboard;
