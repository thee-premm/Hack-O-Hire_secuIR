import React from 'react';
import { List, ListItem, ListItemAvatar, Avatar, Box, Typography, Chip } from '@mui/material';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';

const AlertCard = ({ incidents }) => {
  const getIcon = (risk) => {
    if (risk > 0.7) return <ErrorOutlineIcon sx={{ color: '#ff4d6d' }} />;
    if (risk > 0.4) return <WarningAmberIcon sx={{ color: '#ffb703' }} />;
    return <InfoOutlinedIcon sx={{ color: '#80ed99' }} />;
  };

  const getBorderColor = (risk) => {
    if (risk > 0.7) return 'rgba(255,77,109,0.25)';
    if (risk > 0.4) return 'rgba(255,183,3,0.25)';
    return 'rgba(128,237,153,0.15)';
  };

  if (!incidents || incidents.length === 0) {
    return (
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
        <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.3)' }}>
          No recent alerts
        </Typography>
      </Box>
    );
  }

  return (
    <List sx={{ height: '100%', overflow: 'auto', py: 0 }}>
      {incidents.map((inc, index) => {
        const risk = inc.playbook_summary?.risk || 0;
        const action = inc.playbook_summary?.action || 'UNKNOWN';
        return (
          <ListItem
            key={index}
            sx={{
              mb: 1,
              borderRadius: '10px',
              border: `1px solid ${getBorderColor(risk)}`,
              bgcolor: 'rgba(0,0,0,0.15)',
              transition: 'all 0.2s',
              '&:hover': { bgcolor: 'rgba(0,0,0,0.25)', transform: 'translateX(4px)' },
            }}
          >
            <ListItemAvatar sx={{ minWidth: 40 }}>
              <Avatar sx={{ bgcolor: 'transparent', width: 32, height: 32 }}>{getIcon(risk)}</Avatar>
            </ListItemAvatar>
            <Box sx={{ flex: 1, minWidth: 0, ml: 0.5 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.8, mb: 0.3 }}>
                <Typography variant="body2" sx={{ fontWeight: 600, fontSize: '0.8rem' }}>
                  {inc.incident?.user_id || 'unknown'}
                </Typography>
                <Chip
                  label={`${(risk * 100).toFixed(0)}%`}
                  size="small"
                  sx={{
                    height: 18, fontSize: '0.6rem', fontWeight: 700,
                    bgcolor: risk > 0.7 ? 'rgba(255,77,109,0.15)' : risk > 0.4 ? 'rgba(255,183,3,0.15)' : 'rgba(128,237,153,0.12)',
                    color: risk > 0.7 ? '#ff4d6d' : risk > 0.4 ? '#ffb703' : '#80ed99',
                  }}
                />
              </Box>
              <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.35)', fontSize: '0.65rem' }}>
                {action} &middot; {new Date(inc.timestamp).toLocaleTimeString()}
              </Typography>
            </Box>
          </ListItem>
        );
      })}
    </List>
  );
};

export default AlertCard;
