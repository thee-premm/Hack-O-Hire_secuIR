import React from 'react';
import { AppBar, Toolbar, Typography, Box, Chip } from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import FiberManualRecordIcon from '@mui/icons-material/FiberManualRecord';

const Header = () => {
  return (
    <AppBar
      position="sticky"
      elevation={0}
      sx={{
        bgcolor: 'rgba(16,16,32,0.85)',
        backdropFilter: 'blur(20px)',
        borderBottom: '1px solid rgba(0,180,216,0.15)',
      }}
    >
      <Toolbar sx={{ justifyContent: 'space-between', py: 0.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Box
            sx={{
              width: 40, height: 40,
              borderRadius: '12px',
              background: 'linear-gradient(135deg, #00b4d8, #7209b7)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}
          >
            <SecurityIcon sx={{ fontSize: 24, color: '#fff' }} />
          </Box>
          <Typography
            variant="h6"
            sx={{
              fontWeight: 800,
              letterSpacing: '-0.5px',
              background: 'linear-gradient(90deg, #00b4d8, #7209b7, #f72585)',
              backgroundClip: 'text',
              WebkitBackgroundClip: 'text',
              color: 'transparent',
            }}
          >
            SecuIR
          </Typography>
          <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.4)', ml: 1, fontWeight: 300 }}>
            Banking Threat Intelligence
          </Typography>
        </Box>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Chip
            icon={<FiberManualRecordIcon sx={{ fontSize: '10px !important', color: '#00f5d4 !important' }} />}
            label="Live"
            size="small"
            sx={{
              bgcolor: 'rgba(0,245,212,0.08)',
              color: '#00f5d4',
              fontWeight: 600,
              fontSize: '0.7rem',
              border: '1px solid rgba(0,245,212,0.2)',
              '& .MuiChip-icon': { ml: '6px' },
            }}
          />
          <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.3)' }}>
            v2.0 Production
          </Typography>
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default Header;
