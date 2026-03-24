import { memo } from 'react';
import {
    PieChart,
    Pie,
    Cell,
    Tooltip,
    Legend,
    ResponsiveContainer,
} from 'recharts';

const COLORS = {
    TCP: '#58a6ff',
    UDP: '#3fb950',
    DNS: '#d2a8ff',
    HTTP: '#ffa657',
    ICMP: '#79c0ff',
    ARP: '#ff7b72',
    OTHER: '#8b949e',
};

const ProtocolChart = memo(function ProtocolChart({ data }) {
    if (!data || data.length === 0) {
        return (
            <div
                style={{
                    color: '#8b949e',
                    textAlign: 'center',
                    paddingTop: '40px',
                }}
            >
                No data available
            </div>
        );
    }

    return (
        <ResponsiveContainer width="100%" height={200}>
            <PieChart>
                <Pie
                    data={data}
                    dataKey="count"
                    nameKey="protocol"
                    cx="50%"
                    cy="50%"
                    outerRadius={70}
                    labelLine={false}
                    isAnimationActive={false}
                    label={({ protocol, percent }) =>
                        percent > 0.05
                            ? `${protocol} ${(percent * 100).toFixed(0)}%`
                            : ''
                    }
                >
                    {data.map((entry, index) => (
                        <Cell
                            key={index}
                            fill={COLORS[entry.protocol] || COLORS.OTHER}
                        />
                    ))}
                </Pie>
                <Tooltip
                    formatter={(value, name) => [value + ' packets', name]}
                    contentStyle={{
                        background: '#161b22',
                        border: '1px solid #30363d',
                    }}
                    labelStyle={{ color: '#e6edf3' }}
                />
            </PieChart>
        </ResponsiveContainer>
    );
});

export default ProtocolChart;
