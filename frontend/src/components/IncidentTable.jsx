import React from 'react';
import {
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, IconButton, Tooltip, Typography, Box,
} from '@mui/material';
import DescriptionIcon from '@mui/icons-material/Description';

const actionColors = {
  BLOCK_TRANSACTION: { bg: 'rgba(255,77,109,0.12)', text: '#ff4d6d' },
  FREEZE_ACCOUNT: { bg: 'rgba(255,77,109,0.12)', text: '#ff4d6d' },
  TERMINATE_SESSION: { bg: 'rgba(255,77,109,0.12)', text: '#ff4d6d' },
  MFA_CHALLENGE: { bg: 'rgba(255,183,3,0.12)', text: '#ffb703' },
  DELAY_TRANSACTION: { bg: 'rgba(255,183,3,0.12)', text: '#ffb703' },
  MANUAL_REVIEW: { bg: 'rgba(199,125,255,0.12)', text: '#c77dff' },
  NOTIFY_SOC: { bg: 'rgba(199,125,255,0.12)', text: '#c77dff' },
  RESTRICT_SESSION: { bg: 'rgba(0,180,216,0.12)', text: '#00b4d8' },
  LOG_ONLY: { bg: 'rgba(128,237,153,0.1)', text: '#80ed99' },
  REPORT_TO_COMPLIANCE: { bg: 'rgba(255,183,3,0.12)', text: '#ffb703' },
};

const IncidentTable = ({ incidents, riskFilter, onViewPlaybook }) => {
  const filtered = incidents.filter((inc) => {
    const risk = inc.playbook_summary?.risk || 0;
    if (riskFilter === 1) return risk > 0.7;
    if (riskFilter === 2) return risk > 0.4 && risk <= 0.7;
    if (riskFilter === 3) return risk <= 0.4;
    return true;
  });

  if (filtered.length === 0) {
    return (
      <Box sx={{ py: 6, textAlign: 'center' }}>
        <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.3)' }}>
          No incidents match this filter
        </Typography>
      </Box>
    );
  }

  const headerStyle = {
    color: 'rgba(255,255,255,0.45)',
    fontWeight: 600,
    fontSize: '0.7rem',
    textTransform: 'uppercase',
    letterSpacing: '0.6px',
    borderColor: 'rgba(255,255,255,0.06)',
    py: 1.5,
  };

  const cellStyle = {
    borderColor: 'rgba(255,255,255,0.04)',
    py: 1.2,
    fontSize: '0.8rem',
  };

  return (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell sx={headerStyle}>Time</TableCell>
            <TableCell sx={headerStyle}>Incident</TableCell>
            <TableCell sx={headerStyle}>User</TableCell>
            <TableCell sx={headerStyle}>Risk</TableCell>
            <TableCell sx={headerStyle}>Action</TableCell>
            <TableCell sx={headerStyle}>Status</TableCell>
            <TableCell sx={headerStyle} align="center">Playbook</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {filtered.map((inc, idx) => {
            const risk = inc.playbook_summary?.risk || 0;
            const action = inc.playbook_summary?.action || 'UNKNOWN';
            const colors = actionColors[action] || { bg: 'rgba(255,255,255,0.05)', text: '#aaa' };
            const riskColor = risk > 0.7 ? '#ff4d6d' : risk > 0.4 ? '#ffb703' : '#80ed99';

            return (
              <TableRow
                key={idx}
                sx={{
                  transition: 'background 0.15s',
                  '&:hover': { bgcolor: 'rgba(0,180,216,0.04)' },
                }}
              >
                <TableCell sx={cellStyle}>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.5)', fontFamily: 'monospace' }}>
                    {new Date(inc.timestamp).toLocaleTimeString()}
                  </Typography>
                </TableCell>
                <TableCell sx={cellStyle}>
                  <Chip
                    label={inc.incident?.incident_id || 'N/A'}
                    size="small"
                    sx={{
                      fontFamily: 'monospace', fontSize: '0.65rem', height: 22,
                      bgcolor: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.6)',
                      border: '1px solid rgba(255,255,255,0.08)',
                    }}
                  />
                </TableCell>
                <TableCell sx={cellStyle}>
                  <Typography variant="body2" sx={{ fontWeight: 500, fontSize: '0.8rem' }}>
                    {inc.incident?.user_id || 'N/A'}
                  </Typography>
                </TableCell>
                <TableCell sx={cellStyle}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Box sx={{ width: 50, height: 4, borderRadius: 2, bgcolor: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
                      <Box sx={{ width: `${risk * 100}%`, height: '100%', borderRadius: 2, bgcolor: riskColor, transition: 'width 0.3s' }} />
                    </Box>
                    <Typography variant="caption" sx={{ color: riskColor, fontWeight: 700, fontFamily: 'monospace', fontSize: '0.7rem' }}>
                      {(risk * 100).toFixed(0)}%
                    </Typography>
                  </Box>
                </TableCell>
                <TableCell sx={cellStyle}>
                  <Chip
                    label={action.replace(/_/g, ' ')}
                    size="small"
                    sx={{
                      height: 22, fontSize: '0.6rem', fontWeight: 600,
                      bgcolor: colors.bg, color: colors.text,
                      border: `1px solid ${colors.text}22`,
                    }}
                  />
                </TableCell>
                <TableCell sx={cellStyle}>
                  <Chip
                    label={inc.playbook_summary?.requires_approval ? 'Pending' : 'Resolved'}
                    size="small"
                    sx={{
                      height: 20, fontSize: '0.6rem',
                      bgcolor: inc.playbook_summary?.requires_approval ? 'rgba(255,183,3,0.1)' : 'rgba(128,237,153,0.08)',
                      color: inc.playbook_summary?.requires_approval ? '#ffb703' : '#80ed99',
                    }}
                  />
                </TableCell>
                <TableCell sx={cellStyle} align="center">
                  <Tooltip title="View Playbook" arrow>
                    <IconButton
                      size="small"
                      onClick={() => onViewPlaybook(inc)}
                      sx={{ color: 'rgba(255,255,255,0.3)', '&:hover': { color: '#00b4d8' } }}
                    >
                      <DescriptionIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </TableContainer>
  );
};

export default IncidentTable;
