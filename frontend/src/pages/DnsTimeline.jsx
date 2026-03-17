import { useState, useMemo, useRef, useEffect } from 'react'
import {
    ScatterChart,
    Scatter,
    XAxis,
    YAxis,
    Tooltip,
    ResponsiveContainer,
    Cell,
    ReferenceLine,
} from 'recharts'
import { Search, BarChart2, Globe, LineChart, Trophy, FileText, Clock, Activity, Tag, Copy } from 'lucide-react'

function _rootDomain(domain) {
    if (!domain) return ''
    const parts = domain.split('.')
    if (parts.length <= 2) return domain
    return parts.slice(-2).join('.')
}

function _timeToSeconds(timeStr) {
    if (!timeStr) return 0
    const clean = timeStr.split('.')[0] 
    const parts = clean.split(':').map(Number)
    return (parts[0] || 0) * 3600 + (parts[1] || 0) * 60 + (parts[2] || 0)
}

function _secondsToTime(sec) {
    const h = String(Math.floor(sec / 3600)).padStart(2, '0')
    const m = String(Math.floor((sec % 3600) / 60)).padStart(2, '0')
    const s = String(Math.floor(sec % 60)).padStart(2, '0')
    return `${h}:${m}:${s}`
}

function DnsTimeline({ socket }) {
    const { packets } = socket
    
    const [filterText, setFilterText] = useState('')

    const dnsEntries = useMemo(() => {
        return packets
            .filter(pkt => pkt.dns_query)
            .map(pkt => ({
                time:       pkt.time,
                timeSec:    _timeToSeconds(pkt.time),
                domain:     pkt.dns_query,
                rootDomain: _rootDomain(pkt.dns_query),
                src_ip:     pkt.src_ip || '',
            }))
            .reverse() 
    }, [packets])

    const colorMap = useMemo(() => {
        const map = {}
        let colorIdx = 0
        dnsEntries.forEach(e => {
            if (!map[e.rootDomain]) {
                map[e.rootDomain] = DOMAIN_COLORS[colorIdx % DOMAIN_COLORS.length]
                colorIdx++
            }
        })
        return map
    }, [dnsEntries])

    const domainStats = useMemo(() => {
        const counts = {}
        dnsEntries.forEach(e => {
            counts[e.rootDomain] = (counts[e.rootDomain] || 0) + 1
        })
        return Object.entries(counts)
            .map(([domain, count]) => ({ domain, count, color: colorMap[domain] || '#8b949e' }))
            .sort((a, b) => b.count - a.count)
    }, [dnsEntries, colorMap])

    const filteredEntries = useMemo(() => {
        if (!filterText) return dnsEntries
        const q = filterText.toLowerCase()
        return dnsEntries.filter(e =>
            e.domain.toLowerCase().includes(q) ||
            e.src_ip.toLowerCase().includes(q)
        )
    }, [dnsEntries, filterText])

    const scatterData = useMemo(() => {
        const rootList = [...new Set(filteredEntries.map(e => e.rootDomain))]
        return filteredEntries.map(e => ({
            x:      e.timeSec,
            y:      rootList.indexOf(e.rootDomain),
            domain: e.domain,
            rootDomain: e.rootDomain,
            time:   e.time,
            src_ip: e.src_ip,
        }))
    }, [filteredEntries])

    const rootDomainList = useMemo(() => {
        return [...new Set(filteredEntries.map(e => e.rootDomain))]
    }, [filteredEntries])

    const handleCopy = (text) => {
        if (navigator.clipboard) navigator.clipboard.writeText(text)
    }

    return (
        <div className="page-content" style={{ padding: '16px' }}>
            <div style={{ marginBottom: '16px' }}>
                <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#e6edf3', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Search size={22} color="#58a6ff" /> Dòng Thời gian Truy vấn DNS
                </h2>
                <p style={{ color: '#8b949e', fontSize: '12px', marginTop: '4px' }}>
                    Mỗi chấm trên biểu đồ là một lần máy tính hỏi đường (DNS Query).
                    Phát hiện phần mềm nào đang ngầm liên lạc Internet sau lưng bạn.
                </p>
            </div>

            <div style={{
                display: 'flex',
                gap: '12px',
                alignItems: 'center',
                marginBottom: '16px',
                flexWrap: 'wrap',
            }}>
                <div style={{ position: 'relative' }}>
                    <div style={{ position: 'absolute', left: '10px', top: '8px', color: '#8b949e' }}>
                        <Search size={14} />
                    </div>
                    <input
                        type="text"
                        placeholder="Lọc tên miền hoặc IP..."
                        value={filterText}
                        onChange={(e) => setFilterText(e.target.value)}
                        style={{
                            background: '#0d1117',
                            border: '1px solid #30363d',
                            borderRadius: '6px',
                            padding: '8px 12px 8px 32px',
                            color: '#e6edf3',
                            fontSize: '12px',
                            fontFamily: 'monospace',
                            width: '280px',
                            outline: 'none',
                        }}
                    />
                </div>
                <span style={{ color: '#8b949e', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <BarChart2 size={14} strokeWidth={2.5} /> {filteredEntries.length} truy vấn DNS
                    {filterText && ` (tìm thấy từ ${dnsEntries.length} tổng)`}
                </span>
                <span style={{ color: '#58a6ff', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <Globe size={14} strokeWidth={2.5} /> {rootDomainList.length} tên miền gốc
                </span>
            </div>

            <div style={{
                background: '#0d1117',
                border: '1px solid #21262d',
                borderRadius: '8px',
                padding: '16px',
                marginBottom: '16px',
            }}>
                <div style={{
                    fontSize: '13px',
                    fontWeight: 600,
                    color: '#e6edf3',
                    marginBottom: '12px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                }}>
                    <LineChart size={16} color="#d2a8ff" /> Biểu đồ phân tán DNS theo thời gian
                </div>

                {scatterData.length === 0 ? (
                    <div style={{
                        height: '200px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: '#8b949e',
                        fontSize: '12px',
                    }}>
                        Chưa có truy vấn DNS — hãy bắt gói tin và duyệt web
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height={Math.max(200, rootDomainList.length * 30 + 60)}>
                        <ScatterChart margin={{ left: 20, right: 20, top: 10, bottom: 10 }}>
                            <XAxis
                                type="number"
                                dataKey="x"
                                domain={['dataMin - 10', 'dataMax + 10']}
                                tickFormatter={_secondsToTime}
                                tick={{ fill: '#8b949e', fontSize: 10 }}
                                axisLine={{ stroke: '#30363d' }}
                                name="Thời gian"
                            />
                            <YAxis
                                type="number"
                                dataKey="y"
                                domain={[-0.5, rootDomainList.length - 0.5]}
                                ticks={rootDomainList.map((_, i) => i)}
                                tickFormatter={(val) => {
                                    const name = rootDomainList[val]
                                    return name ? (name.length > 20 ? name.substring(0, 18) + '...' : name) : ''
                                }}
                                width={140}
                                tick={{ fill: '#e6edf3', fontSize: 10, fontFamily: 'monospace' }}
                                axisLine={{ stroke: '#30363d' }}
                                name="Tên miền"
                            />
                            <Tooltip
                                content={({ active, payload }) => {
                                    if (!active || !payload || !payload.length) return null
                                    const d = payload[0].payload
                                    return (
                                        <div style={{
                                            background: '#161b22',
                                            border: '1px solid #30363d',
                                            borderRadius: '6px',
                                            padding: '10px 14px',
                                            fontSize: '11px',
                                            fontFamily: 'monospace',
                                            color: '#e6edf3',
                                            lineHeight: '1.6',
                                        }}>
                                            <div style={{display: 'flex', alignItems: 'center', gap: '4px'}}><Clock size={12} /> <strong>{d.time}</strong></div>
                                            <div style={{display: 'flex', alignItems: 'center', gap: '4px'}}><Globe size={12} /> <span style={{ color: colorMap[d.rootDomain] || '#58a6ff' }}>{d.domain}</span></div>
                                            <div style={{display: 'flex', alignItems: 'center', gap: '4px'}}><Activity size={12} /> {d.src_ip}</div>
                                        </div>
                                    )
                                }}
                            />
                            {rootDomainList.map((_, i) => (
                                <ReferenceLine
                                    key={i}
                                    y={i}
                                    stroke="#21262d"
                                    strokeDasharray="3 3"
                                />
                            ))}
                            <Scatter data={scatterData} isAnimationActive={false}>
                                {scatterData.map((entry, index) => (
                                    <Cell
                                        key={index}
                                        fill={colorMap[entry.rootDomain] || '#58a6ff'}
                                        r={5}
                                    />
                                ))}
                            </Scatter>
                        </ScatterChart>
                    </ResponsiveContainer>
                )}
            </div>

            <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>

                <div style={{
                    background: '#0d1117',
                    border: '1px solid #21262d',
                    borderRadius: '8px',
                    padding: '12px',
                    width: '280px',
                    maxHeight: '400px',
                    overflowY: 'auto',
                    flexShrink: 0,
                }}>
                    <div style={{
                        fontSize: '12px',
                        fontWeight: 600,
                        color: '#e6edf3',
                        marginBottom: '10px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px'
                    }}>
                        <Trophy size={14} color="#e3b341" /> Tần suất truy vấn
                    </div>

                    {domainStats.length === 0 ? (
                        <div style={{ color: '#8b949e', fontSize: '11px', textAlign: 'center', padding: '20px' }}>
                            Chưa có dữ liệu
                        </div>
                    ) : (
                        domainStats.map((item, idx) => (
                            <div
                                key={item.domain}
                                style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'space-between',
                                    padding: '5px 6px',
                                    borderRadius: '4px',
                                    marginBottom: '2px',
                                    cursor: 'pointer',
                                    transition: 'background 0.15s',
                                }}
                                onClick={() => setFilterText(item.domain)}
                                onMouseEnter={(e) => e.currentTarget.style.background = '#161b22'}
                                onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                            >
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <div style={{
                                        width: '8px',
                                        height: '8px',
                                        borderRadius: '50%',
                                        background: item.color,
                                        flexShrink: 0,
                                    }} />
                                    <span style={{
                                        fontFamily: 'monospace',
                                        fontSize: '11px',
                                        color: '#e6edf3',
                                    }}>
                                        {item.domain}
                                    </span>
                                </div>
                                <span style={{
                                    fontFamily: 'monospace',
                                    fontSize: '10px',
                                    color: item.color,
                                    fontWeight: 600,
                                    background: `${item.color}15`,
                                    padding: '2px 6px',
                                    borderRadius: '10px',
                                }}>
                                    {item.count}
                                </span>
                            </div>
                        ))
                    )}
                </div>

                <div style={{
                    flex: 1,
                    minWidth: '400px',
                    background: '#0d1117',
                    border: '1px solid #21262d',
                    borderRadius: '8px',
                    padding: '12px',
                    maxHeight: '400px',
                    overflowY: 'auto',
                }}>
                    <div style={{
                        fontSize: '12px',
                        fontWeight: 600,
                        color: '#e6edf3',
                        marginBottom: '10px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px'
                    }}>
                        <FileText size={14} color="#8b949e" /> Chi tiết từng truy vấn
                    </div>

                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px', fontFamily: 'monospace' }}>
                        <thead>
                            <tr style={{
                                position: 'sticky',
                                top: 0,
                                background: '#0d1117',
                                zIndex: 1,
                            }}>
                                <th style={thStyle}><div style={{display:'flex', alignItems:'center', gap:'4px'}}><Clock size={12}/> Thời gian</div></th>
                                <th style={thStyle}><div style={{display:'flex', alignItems:'center', gap:'4px'}}><Activity size={12}/> IP Nguồn</div></th>
                                <th style={thStyle}><div style={{display:'flex', alignItems:'center', gap:'4px'}}><Globe size={12}/> Tên miền truy vấn</div></th>
                                <th style={thStyle}><div style={{display:'flex', alignItems:'center', gap:'4px'}}><Tag size={12}/> Domain gốc</div></th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredEntries.map((e, index) => (
                                <tr
                                    key={index}
                                    style={{ borderBottom: '1px solid #21262d' }}
                                    onMouseEnter={(ev) => ev.currentTarget.style.background = '#161b22'}
                                    onMouseLeave={(ev) => ev.currentTarget.style.background = 'transparent'}
                                >
                                    <td style={{ ...tdStyle, color: '#8b949e', width: '100px' }}>
                                        {e.time}
                                    </td>
                                    <td style={{ ...tdStyle, color: '#58a6ff', width: '120px' }}>
                                        {e.src_ip}
                                    </td>
                                    <td style={{ ...tdStyle, color: '#e6edf3' }}>
                                        <span
                                            style={{ cursor: 'pointer', display:'flex', alignItems:'center', gap:'6px' }}
                                            title="Click để copy"
                                            onClick={() => handleCopy(e.domain)}
                                        >
                                            {e.domain}
                                            <Copy size={12} color="#8b949e" style={{opacity: 0.5}} />
                                        </span>
                                    </td>
                                    <td style={{ ...tdStyle, width: '120px' }}>
                                        <span style={{
                                            color: colorMap[e.rootDomain] || '#8b949e',
                                            fontWeight: 600,
                                        }}>
                                            {e.rootDomain}
                                        </span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    )
}

const thStyle = {
    textAlign: 'left',
    padding: '6px 8px',
    color: '#8b949e',
    fontWeight: 600,
    fontSize: '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    borderBottom: '2px solid #30363d',
}

const tdStyle = {
    padding: '5px 8px',
    whiteSpace: 'nowrap',
}

export default DnsTimeline
