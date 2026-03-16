import { memo } from 'react';
import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    Tooltip,
    ResponsiveContainer,
    CartesianGrid,
} from 'recharts';

const TimeChart = memo(function TimeChart({ data }) {
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
            <LineChart data={data} margin={{ left: 0, right: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                <XAxis
                    dataKey="time"
                    tick={{ fill: '#8b949e', fontSize: 10 }}
                    axisLine={{ stroke: '#30363d' }}
                    // Chỉ hiện mỗi 5 nhãn để tránh chật
                    interval="preserveStartEnd"
                />
                <YAxis
                    tick={{ fill: '#8b949e', fontSize: 11 }}
                    axisLine={{ stroke: '#30363d' }}
                    width={30}
                />
                <Tooltip
                    formatter={(value) => [value + ' gói', 'Số gói tin']}
                    contentStyle={{
                        background: '#161b22',
                        border: '1px solid #30363d',
                    }}
                    labelStyle={{ color: '#8b949e', fontSize: 11 }}
                />
                <Line
                    type="monotone"
                    dataKey="count"
                    stroke="#58a6ff"
                    strokeWidth={2}
                    dot={false} // không hiện chấm tròn — trông gọn hơn
                    activeDot={{ r: 4, fill: '#58a6ff' }}
                    isAnimationActive={false}
                />
            </LineChart>
        </ResponsiveContainer>
    );
});

export default TimeChart;
