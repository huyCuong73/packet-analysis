import { memo, useMemo } from 'react'

// Tạo màu nền dựa trên mức độ hoạt động (0 → đen, cao → đỏ cam)
function _heatColor(count, maxCount) {
    if (!count || count === 0) return 'transparent'
    const ratio = Math.min(count / Math.max(maxCount, 1), 1)

    if (ratio < 0.25) return 'rgba(88, 166, 255, 0.2)'   // xanh nhạt
    if (ratio < 0.50) return 'rgba(88, 166, 255, 0.45)'   // xanh vừa
    if (ratio < 0.75) return 'rgba(227, 179, 65, 0.55)'   // vàng cam
    return 'rgba(248, 81, 73, 0.7)'                        // đỏ — nóng nhất
}

const PortActivityChart = memo(function PortActivityChart({ data }) {
    const { ports = [], timeSlots = [], matrix = {} } = data || {}

    // Tìm giá trị lớn nhất trong toàn bộ ma trận để scale màu
    const maxCount = useMemo(() => {
        let max = 0
        for (const time of timeSlots) {
            for (const p of ports) {
                const v = matrix[time]?.[p.port] || 0
                if (v > max) max = v
            }
        }
        return max
    }, [timeSlots, ports, matrix])

    if (timeSlots.length === 0) {
        return (
            <div style={{
                color: '#8b949e',
                textAlign: 'center',
                paddingTop: '40px',
                fontSize: '12px',
            }}>
                Chưa có dữ liệu
            </div>
        )
    }

    // Giới hạn hiển thị 15 cột thời gian gần nhất
    const visibleSlots = timeSlots.slice(-15)

    return (
        <div style={{ overflowX: 'auto', width: '100%' }}>
            <table style={{
                borderCollapse: 'collapse',
                width: '100%',
                fontSize: '10px',
                fontFamily: 'monospace',
            }}>
                {/* Header: thời gian */}
                <thead>
                    <tr>
                        <th style={{
                            textAlign: 'left',
                            color: '#8b949e',
                            padding: '2px 6px',
                            position: 'sticky',
                            left: 0,
                            background: '#0d1117',
                            zIndex: 1,
                            minWidth: '60px',
                        }}>
                            Port
                        </th>
                        {visibleSlots.map(t => (
                            <th key={t} style={{
                                color: '#8b949e',
                                padding: '2px 4px',
                                fontWeight: 400,
                                whiteSpace: 'nowrap',
                            }}>
                                {t}
                            </th>
                        ))}
                    </tr>
                </thead>

                {/* Body: mỗi hàng = 1 port */}
                <tbody>
                    {ports.map(p => {
                        // Chỉ hiện port nếu có ít nhất 1 ô có dữ liệu
                        const hasData = visibleSlots.some(
                            t => (matrix[t]?.[p.port] || 0) > 0
                        )
                        if (!hasData) return null

                        return (
                            <tr key={p.port}>
                                <td style={{
                                    color: '#e6edf3',
                                    padding: '3px 6px',
                                    whiteSpace: 'nowrap',
                                    position: 'sticky',
                                    left: 0,
                                    background: '#0d1117',
                                    zIndex: 1,
                                    borderRight: '1px solid #21262d',
                                }}>
                                    {p.label}
                                    <span style={{
                                        color: '#484f58',
                                        marginLeft: '3px',
                                    }}>
                                        :{p.port}
                                    </span>
                                </td>
                                {visibleSlots.map(t => {
                                    const count = matrix[t]?.[p.port] || 0
                                    return (
                                        <td
                                            key={t}
                                            title={count > 0
                                                ? `${p.label} (${p.port}) lúc ${t}: ${count} gói`
                                                : ''}
                                            style={{
                                                padding: '2px',
                                                textAlign: 'center',
                                                width: '35px',
                                                minWidth: '35px',
                                            }}
                                        >
                                            <div style={{
                                                width: '100%',
                                                height: '24px',
                                                borderRadius: '3px',
                                                background: _heatColor(count, maxCount),
                                                display: 'flex',
                                                alignItems: 'center',
                                                justifyContent: 'center',
                                                color: count > 0
                                                    ? '#e6edf3' : 'transparent',
                                                fontSize: '10px',
                                                fontWeight: 600,
                                            }}>
                                                {count > 0 ? count : ''}
                                            </div>
                                        </td>
                                    )
                                })}
                            </tr>
                        )
                    })}
                </tbody>
            </table>

            {/* Chú thích màu */}
            <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                marginTop: '8px',
                justifyContent: 'flex-end',
                fontSize: '9px',
                color: '#8b949e',
            }}>
                <span>Ít</span>
                {['rgba(88,166,255,0.2)', 'rgba(88,166,255,0.45)',
                  'rgba(227,179,65,0.55)', 'rgba(248,81,73,0.7)'].map((c, i) => (
                    <div key={i} style={{
                        width: '14px',
                        height: '10px',
                        borderRadius: '2px',
                        background: c,
                    }} />
                ))}
                <span>Nhiều</span>
            </div>
        </div>
    )
})

export default PortActivityChart
