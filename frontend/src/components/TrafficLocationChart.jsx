import { memo } from 'react'
import {
    PieChart,
    Pie,
    Cell,
    Tooltip,
    ResponsiveContainer,
} from 'recharts'

const TrafficLocationChart = memo(function TrafficLocationChart({ data = [] }) {
    if (data.length === 0) {
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

    const total = data.reduce((s, d) => s + d.value, 0)

    return (
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {/* Donut chart */}
            <ResponsiveContainer width="50%" height={180}>
                <PieChart>
                    <Pie
                        data={data}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        innerRadius={40}
                        outerRadius={65}
                        isAnimationActive={false}
                        strokeWidth={0}
                    >
                        {data.map((entry, i) => (
                            <Cell key={i} fill={entry.color} />
                        ))}
                    </Pie>
                    <Tooltip
                        formatter={(value, name) => [
                            `${value} gói (${(value / total * 100).toFixed(1)}%)`,
                            name
                        ]}
                        contentStyle={{
                            background: '#161b22',
                            border: '1px solid #30363d',
                            fontSize: '11px',
                        }}
                    />
                </PieChart>
            </ResponsiveContainer>

            {/* Legend tùy chỉnh */}
            <div style={{ flex: 1 }}>
                {data.map((d, i) => (
                    <div key={i} style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '6px 0',
                        borderBottom: i < data.length - 1
                            ? '1px solid #21262d' : 'none',
                    }}>
                        <div style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '8px',
                        }}>
                            <span style={{
                                width: '10px',
                                height: '10px',
                                borderRadius: '50%',
                                background: d.color,
                                display: 'inline-block',
                            }} />
                            <span style={{
                                color: '#e6edf3',
                                fontSize: '12px',
                            }}>
                                {d.name}
                            </span>
                        </div>
                        <div style={{ textAlign: 'right' }}>
                            <span style={{
                                color: d.color,
                                fontWeight: 600,
                                fontSize: '13px',
                                fontFamily: 'monospace',
                            }}>
                                {d.value}
                            </span>
                            <span style={{
                                color: '#8b949e',
                                fontSize: '10px',
                                marginLeft: '4px',
                            }}>
                                ({(d.value / total * 100).toFixed(0)}%)
                            </span>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    )
})

export default TrafficLocationChart
