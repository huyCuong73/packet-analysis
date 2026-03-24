import { memo } from 'react';
import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    Tooltip,
    ResponsiveContainer,
    Cell,
} from 'recharts';
import { Copy } from 'lucide-react';

const TopIPChart = memo(function TopIPChart({ data, dnsMap = {} }) {
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
            <BarChart
                data={data}
                layout="vertical"
                margin={{ left: 10, right: 20 }}
            >
                <XAxis
                    type="number"
                    tick={{ fill: '#8b949e', fontSize: 11 }}
                    axisLine={{ stroke: '#30363d' }}
                />
                <YAxis
                    type="category"
                    dataKey="ip"
                    width={130}
                    tick={(props) => {
                        const { x, y, payload } = props;
                        const ip = payload.value;
                        const domain = dnsMap[ip];

                        const handleCopy = (e) => {
                            e.stopPropagation();
                            if (domain && navigator.clipboard) {
                                navigator.clipboard.writeText(domain);
                            }
                        };

                        let displayText = ip;
                        if (domain) {
                            const shortDom = domain.length > 30 ? domain.substring(0, 30) + '...' : domain;
                            displayText = `${ip} (${shortDom})`;
                        }

                        return (
                            <g transform={`translate(${x},${y})`} onClick={handleCopy} style={{ cursor: domain ? 'pointer' : 'default' }}>
                                <text x={domain ? -18 : 0} y={0} dy={4} textAnchor="end" fill={domain ? "#e6edf3" : "#8b949e"} fontSize={11} fontFamily="monospace">
                                    {displayText}
                                </text>
                                {domain && (
                                    <svg x="-14" y="-6" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#8b949e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                        <rect width="14" height="14" x="8" y="8" rx="2" ry="2" /><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
                                    </svg>
                                )}
                            </g>
                        );
                    }}
                    axisLine={{ stroke: '#30363d' }}
                />
                <Tooltip
                    formatter={(value) => [value + ' packets', 'Packet Count']}
                    contentStyle={{
                        background: '#161b22',
                        border: '1px solid #30363d',
                    }}
                    labelStyle={{ color: '#58a6ff', fontFamily: 'monospace' }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]} isAnimationActive={false}>
                    {data.map((_, index) => (
                        <Cell
                            key={index}
                            fill={`rgba(88, 166, 255, ${1 - index * 0.08})`}
                        />
                    ))}
                </Bar>
            </BarChart>
        </ResponsiveContainer>
    );
});

export default TopIPChart;
