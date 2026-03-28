import axios from 'axios';

const API_BASE = 'http://localhost:8000/api';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
  headers: { 'Content-Type': 'application/json' },
});

// WebSocket connection
let ws = null;

export const connectWebSocket = (onMessage) => {
  if (ws && ws.readyState === WebSocket.OPEN) return ws;
  ws = new WebSocket('ws://localhost:8000/ws');
  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    onMessage(data);
  };
  ws.onclose = () => {
    setTimeout(() => connectWebSocket(onMessage), 3000);
  };
  ws.onerror = () => {};
  return ws;
};

export const ingestLog = async (rawLog, formatType = 'json') => {
  const response = await api.post('/ingest', { raw_log: rawLog, format_type: formatType });
  return response.data;
};

export const getIncidents = async (limit = 50, riskMin = null) => {
  const params = { limit };
  if (riskMin !== null) params.risk_min = riskMin;
  const response = await api.get('/incidents', { params });
  return response.data;
};

export const getIncidentDetail = async (incidentId) => {
  const response = await api.get(`/incidents/${incidentId}`);
  return response.data;
};

export const getPlaybook = async (incidentId) => {
  const response = await api.get(`/playbook/${incidentId}`);
  return response.data;
};

export const getStats = async () => {
  const response = await api.get('/stats');
  return response.data;
};

export const healthCheck = async () => {
  const response = await api.get('/health');
  return response.data;
};

export const simulateTraffic = async (count = 10) => {
  const response = await api.post(`/simulate?count=${count}`);
  return response.data;
};

export default api;
