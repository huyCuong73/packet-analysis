import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    Tooltip,
    ResponsiveContainer,
    Cell,
} from 'recharts';

function TopIPChart({ data }) {
    if (!data || data.length === 0) {
        return (
            <div
                style={{
                    color: '#8b949e',
                    textAlign: 'center',
                    paddingTop: '40px',
                }}
            >
                Chưa có dữ liệu
            </div>
        );
    }

    return (
        <ResponsiveContainer width="100%" height={200}>
            <BarChart
                data={data}
                layout="vertical" // bar nằm ngang — dễ đọc IP hơn
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
                    width={110}
                    tick={{
                        fill: '#8b949e',
                        fontSize: 11,
                        fontFamily: 'monospace',
                    }}
                    axisLine={{ stroke: '#30363d' }}
                />
                <Tooltip
                    formatter={(value) => [value + ' gói', 'Số gói tin']}
                    contentStyle={{
                        background: '#161b22',
                        border: '1px solid #30363d',
                    }}
                    labelStyle={{ color: '#58a6ff', fontFamily: 'monospace' }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {data.map((_, index) => (
                        // Gradient màu từ đậm → nhạt
                        <Cell
                            key={index}
                            fill={`rgba(88, 166, 255, ${1 - index * 0.08})`}
                        />
                    ))}
                </Bar>
            </BarChart>
        </ResponsiveContainer>
    );
}

export default TopIPChart;
