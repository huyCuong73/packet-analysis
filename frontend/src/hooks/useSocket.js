import { useEffect, useState } from 'react';
import socket from '../services/socket';

export function useSocket() {
    const [isConnected, setIsConnected] = useState(false);
    const [isCapturing, setIsCapturing] = useState(false);
    const [packets, setPackets] = useState([]);
    const [currentSessionId, setCurrentSessionId] = useState(null);
    const [currentSessionName, setCurrentSessionName] = useState('');
    const [dnsMap, setDnsMap] = useState({}); // Lịch sử DNS
    const [isReplaying, setIsReplaying] = useState(false);
    const [replayProgress, setReplayProgress] = useState(0);

    useEffect(() => {
        socket.on('connect', () => setIsConnected(true));
        socket.on('disconnect', () => setIsConnected(false));

        socket.on('dns_resolved', ({ ip, domain }) => {
            setDnsMap((prev) => ({ ...prev, [ip]: domain }));
        });

        socket.on('new_packet', (packet) => {
            setPackets((prev) => [packet, ...prev]);
        });

        socket.on('arp_alert', (data) => {
            setArpAlerts(prev => [data, ...prev].slice(0, 50))
        })

        socket.on('capture_status', (data) => {
            const started = data.status === 'started';
            setIsCapturing(started);
            if (!started) {
                setIsReplaying(false);
                setReplayProgress(0);
            }
        });

        // Lắng nghe session mới được tạo
        socket.on('session_created', (data) => {
            setCurrentSessionId(data.session_id);
            setCurrentSessionName(data.name);
        });

        // Lắng nghe progress replay
        socket.on('replay_progress', (data) => {
            setReplayProgress(data.progress);
            if (data.progress === 100) {
                setTimeout(() => {
                    setIsReplaying(false);
                    setReplayProgress(0);
                }, 2000);
            }
        });

        return () => {
            socket.off('connect');
            socket.off('disconnect');
            socket.off('new_packet');
            socket.off('capture_status');
            socket.off('session_created');
            socket.off('dns_resolved');
            socket.off('replay_progress');
            socket.off('arp_alert')
        };
    }, []);

    const startCapture = (filter = '', name = '', iface = '') => {
        setPackets([]);
        socket.emit('start_capture', { filter, name, interface: iface });
    };

    const stopCapture = () => socket.emit('stop_capture');
    const clearPackets = () => setPackets([]);

    return {
        isConnected,
        isCapturing,
        packets,
        startCapture,
        stopCapture,
        clearPackets,
        currentSessionId,
        currentSessionName,
        dnsMap,
        isReplaying,
        setIsReplaying,
        replayProgress,
        arpAlerts,
    };
}
