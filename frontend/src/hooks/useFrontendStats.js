import { useMemo } from 'react';

export function useFrontendStats(packets) {
    const protocolStats = useMemo(() => {
        const counts = packets.reduce((acc, pkt) => {
            const proto = pkt.protocol || 'OTHER';
            acc[proto] = (acc[proto] || 0) + 1;
            return acc;
        }, {});

        return Object.entries(counts)
            .map(([protocol, count]) => ({ protocol, count }))
            .sort((a, b) => b.count - a.count);
    }, [packets]);

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
            .slice(0, 10); 
    }, [packets]);

    const timeStats = useMemo(() => {
        const counts = packets.reduce((acc, pkt) => {
            if (!pkt.time) return acc;
            const timeSec = pkt.time.split('.')[0];
            acc[timeSec] = (acc[timeSec] || 0) + 1;
            return acc;
        }, {});

        return Object.entries(counts)
            .map(([time, count]) => ({ time, count }))
            .sort((a, b) => a.time.localeCompare(b.time)); 
    }, [packets]);

    const topTalkers = useMemo(() => {
        const bytes = packets.reduce((acc, pkt) => {
            const ip = pkt.src_ip
            if (!ip) return acc
            acc[ip] = (acc[ip] || 0) + (pkt.length || 0)
            return acc
        }, {})

        return Object.entries(bytes)
            .map(([ip, totalBytes]) => ({
                ip,
                totalBytes,
                totalMB: parseFloat((totalBytes / (1024 * 1024)).toFixed(2))
            }))
            .sort((a, b) => b.totalBytes - a.totalBytes)
            .slice(0, 5)  
    }, [packets])

    const trafficLocation = useMemo(() => {
        const counts = { lan: 0, internet: 0, multicast: 0 }

        packets.forEach(pkt => {
            const dst = pkt.dst_ip
            if (!dst) return

            if (_isPrivateIP(dst))         counts.lan++
            else if (_isMulticast(dst))    counts.multicast++
            else                           counts.internet++
        })

        return [
            { name: 'Mạng LAN',    value: counts.lan,       color: '#3fb950' },
            { name: 'Internet',     value: counts.internet,  color: '#58a6ff' },
            { name: 'Multicast',    value: counts.multicast, color: '#8b949e' },
        ].filter(d => d.value > 0)
    }, [packets])

    const portActivity = useMemo(() => {
        const WATCHED_PORTS = [
            { port: 443,  label: 'HTTPS' },
            { port: 80,   label: 'HTTP' },
            { port: 53,   label: 'DNS' },
            { port: 22,   label: 'SSH' },
            { port: 3389, label: 'RDP' },
            { port: 21,   label: 'FTP' },
            { port: 25,   label: 'SMTP' },
            { port: 3306, label: 'MySQL' },
            { port: 8080, label: 'HTTP-Alt' },
        ]
        
        const dynamicPortCounts = {}
        const defaultPortSet = new Set(WATCHED_PORTS.map(p => p.port))

        packets.forEach(pkt => {
            const p = pkt.dst_port || pkt.src_port
            if (p && !defaultPortSet.has(p)) {
                dynamicPortCounts[p] = (dynamicPortCounts[p] || 0) + 1
            }
        })

        const topDynamic = Object.entries(dynamicPortCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3)
            .map(([portStr]) => ({ port: parseInt(portStr), label: 'Other' }))
            
        const finalPorts = [...WATCHED_PORTS, ...topDynamic]
        const finalPortSet = new Set(finalPorts.map(p => p.port))

        const matrix = {}

        let maxTimeStr = ''
        packets.forEach(pkt => {
            if (!pkt.time) return
            const timeMin = pkt.time.substring(0, 5) 
            if (timeMin > maxTimeStr) maxTimeStr = timeMin

            const dport = pkt.dst_port
            const sport = pkt.src_port

            const matchedPort = finalPortSet.has(dport) ? dport
                              : finalPortSet.has(sport) ? sport
                              : null
            if (!matchedPort) return

            if (!matrix[timeMin]) matrix[timeMin] = {}
            matrix[timeMin][matchedPort] = (matrix[timeMin][matchedPort] || 0) + 1
        })

        let timeSlots = []
        if (maxTimeStr) {
            const [hh, mm] = maxTimeStr.split(':').map(Number)
            let date = new Date()
            date.setHours(hh, mm, 0, 0)
            
            for (let i = 14; i >= 0; i--) {
                const past = new Date(date.getTime() - i * 60000)
                const h = String(past.getHours()).padStart(2, '0')
                const m = String(past.getMinutes()).padStart(2, '0')
                timeSlots.push(`${h}:${m}`)
            }
        } else {
            let date = new Date()
            for (let i = 14; i >= 0; i--) {
                const past = new Date(date.getTime() - i * 60000)
                const h = String(past.getHours()).padStart(2, '0')
                const m = String(past.getMinutes()).padStart(2, '0')
                timeSlots.push(`${h}:${m}`)
            }
        }

        return {
            ports: finalPorts,
            timeSlots,
            matrix,
        }
    }, [packets])

    const dnsTimeline = useMemo(() => {
        return packets
            .filter(pkt => pkt.dns_query)   
            .map(pkt => ({
                time:   pkt.time,
                domain: pkt.dns_query,
                src_ip: pkt.src_ip || '',
                dst_ip: pkt.dst_ip || '',
            }))
            .reverse()  
    }, [packets])

    const credentialsList = useMemo(() => {
        return packets
            .filter(pkt => pkt.credentials && pkt.credentials.length > 0)
            .map(pkt => ({
                id:          pkt.id,
                time:        pkt.time,
                src_ip:      pkt.src_ip || '',
                dst_ip:      pkt.dst_ip || '',
                credentials: pkt.credentials 
            }))
            .reverse();
    }, [packets])

    return {
        protocolStats,
        topIPs,
        timeStats,
        totalPackets: packets.length,
        topTalkers,
        trafficLocation,
        portActivity,
        dnsTimeline,
        credentialsList,
    };
}

function _isPrivateIP(ip) {
    if (!ip) return false
    if (ip.startsWith('10.'))  return true
    if (ip.startsWith('192.168.')) return true
    if (ip.startsWith('127.')) return true
    if (ip.startsWith('172.')) {
        const second = parseInt(ip.split('.')[1])
        if (second >= 16 && second <= 31) return true
    }
    return false
}

function _isMulticast(ip) {
    if (!ip) return false
    if (ip === '255.255.255.255') return true
    const first = parseInt(ip.split('.')[0])
    return first >= 224 && first <= 239
}
