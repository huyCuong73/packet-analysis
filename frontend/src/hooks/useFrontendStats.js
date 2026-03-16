import { useMemo } from 'react';

export function useFrontendStats(packets) {
    // 1. Phân tích thống kê Giao thức (Protocol)
    const protocolStats = useMemo(() => {
        const counts = packets.reduce((acc, pkt) => {
            const proto = pkt.protocol || 'OTHER';
            acc[proto] = (acc[proto] || 0) + 1;
            return acc;
        }, {});

        // Chuyển Object thành Mảng và sắp xếp giảm dần
        return Object.entries(counts)
            .map(([protocol, count]) => ({ protocol, count }))
            .sort((a, b) => b.count - a.count);
    }, [packets]);

    // 2. Phân tích Top 10 IP Nguồn
    const topIPs = useMemo(() => {
        const counts = packets.reduce((acc, pkt) => {
            const ip = pkt.src_ip;
            if (ip) {
                acc[ip] = (acc[ip] || 0) + 1;
            }
            return acc;
        }, {});

        return Object.entries(counts)
            .map(([ip, count]) => ({ ip, count }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 10); // Lấy 10 IP cao nhất
    }, [packets]);

    // 3. Phân tích Traffic theo thời gian (gom nhóm theo giây)
    const timeStats = useMemo(() => {
        const counts = packets.reduce((acc, pkt) => {
            if (!pkt.time) return acc;
            // Cắt mili-giây, ví dụ "14:32:01.123" -> "14:32:01"
            const timeSec = pkt.time.split('.')[0];
            acc[timeSec] = (acc[timeSec] || 0) + 1;
            return acc;
        }, {});

        return Object.entries(counts)
            .map(([time, count]) => ({ time, count }))
            .sort((a, b) => a.time.localeCompare(b.time)); // Sắp xếp theo chuỗi thời gian tăng dần
    }, [packets]);

    return {
        protocolStats,
        topIPs,
        timeStats,
        totalPackets: packets.length,
    };
}
