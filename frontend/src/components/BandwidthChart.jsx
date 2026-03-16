import { useMemo } from 'react'
import { Trophy, BarChart2, Copy } from 'lucide-react'

// Màu sắc theo mức độ băng thông
function _getColor(mb, maxMB) {
    const ratio = maxMB > 0 ? mb / maxMB : 0
    if (ratio > 0.75) return '#f85149'  // đỏ   — ngốn nhiều nhất
    if (ratio > 0.40) return '#e3b341'  // vàng  — trung bình
    return '#3fb950'                    // xanh  — bình thường
}

// Rút gọn IP dài
function _shortIP(ip, domain) {
    if (domain) {
        const shortDom = domain.length > 30 ? domain.substring(0, 30) + '...' : domain;
        return `${ip} (${shortDom})`;
    }
    if (!ip) return '?'
    // IPv6 rút gọn
    if (ip.includes(':')) return ip.substring(0, 12) + '...'
    return ip
}

// Format số bytes cho dễ đọc
function _formatBytes(bytes) {
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${bytes} B`
}

function BandwidthChart({ data = [], dnsMap = {} }) {
    const maxBytes = useMemo(
        () => Math.max(...data.map(d => d.totalBytes), 1),
        [data]
    )

    const handleCopyDomain = (e, domain) => {
        e.stopPropagation();
        if (domain && navigator.clipboard) {
            navigator.clipboard.writeText(domain);
        }
    };

    if (data.length === 0) {
        return (
            <div style={{
                height: '100%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#8b949e',
                fontSize: '12px',
                flexDirection: 'column',
                gap: '8px'
            }}>
                <BarChart2 size={24} color="#8b949e" />
                <span>Chưa có dữ liệu</span>
            </div>
        )
    }

    return (
        <div style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '10px',
            padding: '4px 0',
            width: '100%'
        }}>

            {data.map((item, index) => {
                const pct = (item.totalBytes / maxBytes) * 100
                const color = _getColor(item.totalMB, data[0]?.totalMB)
                const domain = dnsMap[item.ip]

                return (
                    <div key={item.ip}>

                        {/* Hàng thông tin: số thứ tự + IP + dung lượng */}
                        <div style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            marginBottom: '4px'
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                {/* Thứ hạng */}
                                <span style={{
                                    fontSize: '10px',
                                    color: index === 0 ? '#e3b341' : '#8b949e',
                                    fontWeight: index === 0 ? 700 : 400,
                                    width: '16px',
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'center'
                                }}>
                                    {index === 0 ? <Trophy size={14} /> : `#${index + 1}`}
                                </span>

                                {/* IP */}
                                <span style={{
                                    fontFamily: 'monospace',
                                    fontSize: '12px',
                                    color: '#e6edf3'
                                }} title={domain ? `${domain} (${item.ip})` : item.ip}>
                                    {_shortIP(item.ip, domain)}
                                    {domain && (
                                        <span 
                                            title="Copy Domain" 
                                            onClick={(e) => handleCopyDomain(e, domain)}
                                            style={{ cursor: 'pointer', marginLeft: '6px', opacity: 0.5, display: 'inline-flex', alignItems: 'center' }}
                                        >
                                            <Copy size={12} />
                                        </span>
                                    )}
                                </span>
                            </div>

                            {/* Dung lượng */}
                            <span style={{
                                fontFamily: 'monospace',
                                fontSize: '11px',
                                color: color,
                                fontWeight: 600
                            }}>
                                {_formatBytes(item.totalBytes)}
                            </span>
                        </div>

                        {/* Racing bar */}
                        <div style={{
                            width: '100%',
                            height: '8px',
                            background: '#21262d',
                            borderRadius: '4px',
                            overflow: 'hidden'
                        }}>
                            <div style={{
                                width: `${pct}%`,
                                height: '100%',
                                background: color,
                                borderRadius: '4px',
                                // Hiệu ứng racing — thanh chạy mượt
                                transition: 'width 0.6s cubic-bezier(0.4, 0, 0.2, 1)',
                                boxShadow: index === 0 ? `0 0 8px ${color}` : 'none'
                            }} />
                        </div>

                    </div>
                )
            })}

        </div>
    )
}

export default BandwidthChart