import React from 'react';
import { Grid, Paper, Typography, Box } from '@mui/material';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import GppBadIcon from '@mui/icons-material/GppBad';
import RemoveModeratorIcon from '@mui/icons-material/RemoveModerator';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';

const MetricsCards = ({ stats }) => {
  const d = stats || { total_incidents: 0, risk_distribution: { high: 0, medium: 0, low: 0 } };

  const cards = [
    {
      title: 'Total Incidents',
      value: d.total_incidents,
      icon: <WarningAmberIcon />,
      gradient: 'linear-gradient(135deg, #7209b7 0%, #560bad 100%)',
      accent: '#c77dff',
    },
    {
      title: 'Critical',
      value: d.risk_distribution.high,
      icon: <GppBadIcon />,
      gradient: 'linear-gradient(135deg, #d00000 0%, #9d0208 100%)',
      accent: '#ff4d6d',
    },
    {
      title: 'Medium Risk',
      value: d.risk_distribution.medium,
      icon: <RemoveModeratorIcon />,
      gradient: 'linear-gradient(135deg, #e85d04 0%, #dc2f02 100%)',
      accent: '#ffb703',
    },
    {
      title: 'Low Risk',
      value: d.risk_distribution.low,
      icon: <VerifiedUserIcon />,
      gradient: 'linear-gradient(135deg, #007f5f 0%, #2b9348 100%)',
      accent: '#80ed99',
    },
  ];

  return (
    <Grid container spacing={2.5}>
      {cards.map((card, idx) => (
        <Grid item xs={12} sm={6} md={3} key={idx}>
          <Paper
            elevation={0}
            sx={{
              p: 2.5,
              background: 'rgba(22,22,44,0.6)',
              backdropFilter: 'blur(12px)',
              border: '1px solid rgba(255,255,255,0.06)',
              borderRadius: '16px',
              position: 'relative',
              overflow: 'hidden',
              transition: 'all 0.3s cubic-bezier(0.4,0,0.2,1)',
              '&:hover': {
                transform: 'translateY(-4px)',
                borderColor: 'rgba(255,255,255,0.12)',
                boxShadow: `0 12px 40px rgba(0,0,0,0.4)`,
              },
              '&::before': {
                content: '""',
                position: 'absolute',
                top: 0, left: 0, right: 0,
                height: '3px',
                background: card.gradient,
              },
            }}
          >
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <Box>
                <Typography
                  variant="caption"
                  sx={{ color: 'rgba(255,255,255,0.45)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.8px', fontSize: '0.65rem' }}
                >
                  {card.title}
                </Typography>
                <Typography
                  variant="h3"
                  sx={{ fontWeight: 800, color: card.accent, mt: 0.5, lineHeight: 1, fontFamily: '"Inter", monospace' }}
                >
                  {card.value}
                </Typography>
              </Box>
              <Box
                sx={{
                  width: 44, height: 44,
                  borderRadius: '12px',
                  background: card.gradient,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  opacity: 0.9,
                  '& svg': { fontSize: 22, color: '#fff' },
                }}
              >
                {card.icon}
              </Box>
            </Box>
          </Paper>
        </Grid>
      ))}
    </Grid>
  );
};

export default MetricsCards;
