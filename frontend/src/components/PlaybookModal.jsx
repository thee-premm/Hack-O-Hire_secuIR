import React, { useState, useEffect } from 'react';
import {
  Modal, Box, Typography, Paper, Chip, Divider,
  List, ListItem, ListItemText, ListItemIcon,
  IconButton, Button, Stepper, Step, StepLabel,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import DescriptionIcon from '@mui/icons-material/Description';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import SearchIcon from '@mui/icons-material/Search';
import GavelIcon from '@mui/icons-material/Gavel';
import { getPlaybook } from '../services/api';

const modalStyle = {
  position: 'absolute',
  top: '50%',
  left: '50%',
  transform: 'translate(-50%, -50%)',
  width: '72%',
  maxWidth: 920,
  maxHeight: '85vh',
  bgcolor: '#0e0e1a',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '16px',
  boxShadow: '0 40px 80px rgba(0,0,0,0.6)',
  overflow: 'auto',
};

const PlaybookModal = ({ incident, open, onClose }) => {
  const [playbook, setPlaybook] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (open && incident) loadPlaybook();
  }, [open, incident]);

  const loadPlaybook = async () => {
    setLoading(true);
    try {
      const id = incident.incident?.incident_id;
      if (id) {
        const data = await getPlaybook(id);
        setPlaybook(data);
      }
    } catch {
      // Use inline data if API fails
      setPlaybook(incident.playbook || null);
    } finally {
      setLoading(false);
    }
  };

  if (!open) return null;

  const pb = playbook || incident?.playbook || {};
  const risk = pb.incident_summary?.risk_score || incident?.incident?.final_risk || 0;
  const riskColor = risk > 0.7 ? '#ff4d6d' : risk > 0.4 ? '#ffb703' : '#80ed99';
  const action = pb.decision?.action || incident?.decision?.action_value || 'UNKNOWN';

  return (
    <Modal open={open} onClose={onClose} sx={{ backdropFilter: 'blur(4px)' }}>
      <Box sx={modalStyle}>
        {/* Header */}
        <Box
          sx={{
            p: 3,
            background: 'linear-gradient(135deg, rgba(0,180,216,0.15) 0%, rgba(114,9,183,0.15) 100%)',
            borderBottom: '1px solid rgba(255,255,255,0.06)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
            <Box
              sx={{
                width: 36, height: 36, borderRadius: '10px',
                background: 'linear-gradient(135deg, #00b4d8, #7209b7)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}
            >
              <DescriptionIcon sx={{ fontSize: 20, color: '#fff' }} />
            </Box>
            <Box>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, lineHeight: 1.2 }}>
                Incident Response Playbook
              </Typography>
              <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.4)' }}>
                {pb.playbook_id || 'N/A'}
              </Typography>
            </Box>
          </Box>
          <IconButton onClick={onClose} sx={{ color: 'rgba(255,255,255,0.5)' }}>
            <CloseIcon />
          </IconButton>
        </Box>

        {/* Body */}
        <Box sx={{ p: 3 }}>
          {/* Summary Row */}
          <Box
            sx={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: 2,
              mb: 3,
              p: 2,
              borderRadius: '12px',
              bgcolor: 'rgba(255,255,255,0.02)',
              border: '1px solid rgba(255,255,255,0.04)',
            }}
          >
            {[
              { label: 'Incident ID', value: pb.incident_summary?.incident_id || incident?.incident?.incident_id || '-' },
              { label: 'User', value: pb.incident_summary?.user_id || incident?.incident?.user_id || '-' },
              { label: 'Risk Score', value: `${(risk * 100).toFixed(1)}%`, color: riskColor },
              { label: 'Action', value: action.replace(/_/g, ' ') },
            ].map((item, i) => (
              <Box key={i}>
                <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.35)', fontSize: '0.6rem', textTransform: 'uppercase', letterSpacing: '0.6px' }}>
                  {item.label}
                </Typography>
                <Typography variant="body2" sx={{ fontWeight: 600, mt: 0.3, color: item.color || '#fff', fontFamily: 'monospace' }}>
                  {item.value}
                </Typography>
              </Box>
            ))}
          </Box>

          {/* Decision & Justification */}
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: 'rgba(255,255,255,0.7)' }}>
            <GavelIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: 'text-bottom' }} />
            Decision & Justification
          </Typography>
          <Paper
            sx={{
              p: 2, mb: 3, bgcolor: 'rgba(0,0,0,0.2)',
              border: '1px solid rgba(255,255,255,0.04)',
              borderRadius: '10px',
            }}
          >
            <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.6)', mb: 0.5 }}>
              <strong style={{ color: 'rgba(255,255,255,0.8)' }}>Rule: </strong>
              {pb.decision?.rule_triggered || incident?.decision?.rule_name || '-'}
            </Typography>
            <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.6)' }}>
              <strong style={{ color: 'rgba(255,255,255,0.8)' }}>Justification: </strong>
              {pb.decision?.justification || incident?.decision?.justification || '-'}
            </Typography>
          </Paper>

          {/* Investigation Steps */}
          {pb.investigation_steps && pb.investigation_steps.length > 0 && (
            <>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: 'rgba(255,255,255,0.7)' }}>
                <SearchIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: 'text-bottom' }} />
                Investigation Steps
              </Typography>
              <Paper
                sx={{
                  p: 2, mb: 3, bgcolor: 'rgba(0,0,0,0.2)',
                  border: '1px solid rgba(255,255,255,0.04)',
                  borderRadius: '10px',
                }}
              >
                <Stepper orientation="vertical" activeStep={-1}>
                  {pb.investigation_steps.map((step, i) => (
                    <Step key={i} completed={false}>
                      <StepLabel
                        sx={{
                          '& .MuiStepLabel-label': { color: 'rgba(255,255,255,0.7)', fontSize: '0.8rem' },
                          '& .MuiStepIcon-root': { color: 'rgba(0,180,216,0.3)' },
                        }}
                      >
                        {step.title || step}
                      </StepLabel>
                    </Step>
                  ))}
                </Stepper>
              </Paper>
            </>
          )}

          {/* Approval Workflow */}
          {pb.approval_workflow && (
            <>
              <Divider sx={{ borderColor: 'rgba(255,255,255,0.04)', my: 2 }} />
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  p: 2,
                  bgcolor: pb.approval_workflow.requires_approval ? 'rgba(255,183,3,0.06)' : 'rgba(128,237,153,0.04)',
                  borderRadius: '10px',
                  border: `1px solid ${pb.approval_workflow.requires_approval ? 'rgba(255,183,3,0.15)' : 'rgba(128,237,153,0.1)'}`,
                }}
              >
                <Box>
                  <Typography variant="body2" sx={{ fontWeight: 600, mb: 0.3 }}>
                    {pb.approval_workflow.requires_approval ? 'Approval Required' : 'Auto-Executed'}
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.4)' }}>
                    Approver: {pb.approval_workflow.approver || 'system'}
                  </Typography>
                </Box>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  {pb.approval_workflow.requires_approval && (
                    <Button
                      variant="contained"
                      size="small"
                      startIcon={<CheckCircleIcon />}
                      sx={{
                        bgcolor: '#ffb703',
                        color: '#000',
                        fontWeight: 700,
                        '&:hover': { bgcolor: '#ffc233' },
                        borderRadius: '8px',
                        textTransform: 'none',
                      }}
                    >
                      Approve
                    </Button>
                  )}
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={onClose}
                    sx={{
                      borderColor: 'rgba(255,255,255,0.1)',
                      color: 'rgba(255,255,255,0.5)',
                      borderRadius: '8px',
                      textTransform: 'none',
                    }}
                  >
                    Close
                  </Button>
                </Box>
              </Box>
            </>
          )}
        </Box>
      </Box>
    </Modal>
  );
};

export default PlaybookModal;
