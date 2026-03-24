import { useState, useEffect } from 'react';
import axios from 'axios';

export function useStats(isCapturing) {
    const [protocolStats, setProtocolStats] = useState([]);
    const [topIPs, setTopIPs] = useState([]);
    const [timeStats, setTimeStats] = useState([]);

    const fetchStats = async () => {
        try {
            const [proto, ips, time] = await Promise.all([
                axios.get('http://localhost:5000/api/stats/protocols'),
                axios.get('http://localhost:5000/api/stats/top-ips'),
                axios.get('http://localhost:5000/api/stats/traffic-time'),
            ]);
            setProtocolStats(proto.data);
            setTopIPs(ips.data);
            setTimeStats(time.data);
        } catch (err) {
            console.error('Error fetching stats:', err);
        }
    };

    useEffect(() => {
        fetchStats();

        if (!isCapturing) return;
        const interval = setInterval(fetchStats, 3000);
        return () => clearInterval(interval);
    }, [isCapturing]);

    return { protocolStats, topIPs, timeStats, fetchStats };
}
