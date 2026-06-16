import axios from 'axios';

const API_BASE = '';
const API_KEY  = process.env.NEXT_PUBLIC_DASHBOARD_API_KEY || '';

export const api = axios.create({
    baseURL: API_BASE,
    timeout: 5000,
    headers: API_KEY ? { 'X-API-Key': API_KEY } : {},
});

export const fetcher = (url: string) => api.get(url).then(res => res.data);
