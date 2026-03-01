import axios from 'axios';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8003';

export const api = axios.create({
    baseURL: API_BASE,
    timeout: 5000,
});

export const fetcher = (url: string) => api.get(url).then(res => res.data);
