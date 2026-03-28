import React, { useState, useEffect, useCallback } from 'react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { Container, Box, Snackbar, Alert } from '@mui/material';
import { Toaster, toast } from 'react-hot-toast';
import Header from './components/Header';
import Dashboard from './components/Dashboard';
import { connectWebSocket, getStats, healthCheck } from './services/api';
import './App.css';

const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: '#00b4d8' },
    secondary: { main: '#7209b7' },
    background: {
      default: '#08080f',
      paper: 'rgba(22,22,44,0.6)',
    },
    success: { main: '#80ed99' },
    warning: { main: '#ffb703' },
    error: { main: '#ff4d6d' },
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", sans-serif',
    h4: { fontWeight: 800 },
    h5: { fontWeight: 700 },
  },
  shape: { borderRadius: 12 },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
        },
      },
    },
  },
});

function App() {
  const [stats, setStats] = useState(null);
  const [realtimeIncident, setRealtimeIncident] = useState(null);
  const [backendReady, setBackendReady] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'info' });

  const loadStats = useCallback(async () => {
    try {
      const data = await getStats();
      setStats(data);
      setBackendReady(true);
    } catch {
      setBackendReady(false);
    }
  }, []);

  useEffect(() => {
    loadStats();

    try {
      connectWebSocket((data) => {
        if (data.type === 'new_incident') {
          setRealtimeIncident(data.data);
          const risk = data.data.risk || 0;
          const style = risk > 0.7
            ? { icon: '🚨', style: { background: '#1a0a0a', color: '#ff4d6d', border: '1px solid rgba(255,77,109,0.3)' } }
            : risk > 0.4
            ? { icon: '⚠️', style: { background: '#1a1500', color: '#ffb703', border: '1px solid rgba(255,183,3,0.3)' } }
            : { icon: '✓', style: { background: '#0a1a0a', color: '#80ed99', border: '1px solid rgba(128,237,153,0.3)' } };
          toast(
            `${data.data.user_id}: ${data.data.action}`,
            { duration: 4000, position: 'top-right', ...style }
          );
        }
      });
    } catch {
      // WebSocket may fail if backend isn't running
    }

    const interval = setInterval(loadStats, 15000);
    return () => clearInterval(interval);
  }, [loadStats]);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Toaster
        toastOptions={{
          style: {
            borderRadius: '10px',
            fontSize: '0.8rem',
            fontFamily: '"Inter", sans-serif',
          },
        }}
      />
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          minHeight: '100vh',
          background: 'radial-gradient(ellipse at 20% 50%, rgba(0,180,216,0.04) 0%, transparent 50%), radial-gradient(ellipse at 80% 20%, rgba(114,9,183,0.04) 0%, transparent 50%), #08080f',
        }}
      >
        <Header />
        <Container maxWidth="xl" sx={{ mt: 3, mb: 4, flex: 1 }}>
          {!backendReady && (
            <Alert
              severity="info"
              sx={{
                mb: 2,
                bgcolor: 'rgba(0,180,216,0.08)',
                border: '1px solid rgba(0,180,216,0.2)',
                '& .MuiAlert-icon': { color: '#00b4d8' },
              }}
            >
              Backend not connected. Run <code style={{ color: '#00b4d8' }}>python api_server.py</code> in your mvp directory.
            </Alert>
          )}
          <Dashboard stats={stats} onStatsUpdate={loadStats} realtimeIncident={realtimeIncident} />
        </Container>
      </Box>
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity={snackbar.severity} sx={{ width: '100%' }}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </ThemeProvider>
  );
}

export default App;
