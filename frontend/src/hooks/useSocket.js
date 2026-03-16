import { useEffect, useState } from 'react';
import socket from '../services/socket';

export function useSocket() {
    const [isConnected, setIsConnected] = useState(false);
    const [isCapturing, setIsCapturing] = useState(false);
    const [packets, setPackets] = useState([]);
    const [currentSessionId, setCurrentSessionId] = useState(null); 
    const [currentSessionName, setCurrentSessionName] = useState('');
    const [dnsMap, setDnsMap] = useState({}); // Lịch sử DNS

    useEffect(() => {
        socket.on('connect', () => setIsConnected(true));
        socket.on('disconnect', () => setIsConnected(false));

        socket.on('dns_resolved', ({ ip, domain }) => {
            setDnsMap((prev) => ({ ...prev, [ip]: domain }));
        });

        socket.on('new_packet', (packet) => {
            setPackets((prev) => [packet, ...prev]);
        });

        socket.on('capture_status', (data) => {
            setIsCapturing(data.status === 'started');
        });

        // Lắng nghe session mới được tạo
        socket.on('session_created', (data) => {
            setCurrentSessionId(data.session_id);
            setCurrentSessionName(data.name);
        });

        return () => {
            socket.off('connect');
            socket.off('disconnect');
            socket.off('new_packet');
            socket.off('capture_status');
            socket.off('session_created');
            socket.off('dns_resolved');
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
    };
}
