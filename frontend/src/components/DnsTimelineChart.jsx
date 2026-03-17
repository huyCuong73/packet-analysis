import React, { memo, useRef, useEffect } from 'react'
import { Search, Clock, Activity, Globe, Copy } from 'lucide-react'

const DnsTimelineChart = memo(function DnsTimelineChart({ data = [] }) {
    const bottomRef = useRef(null)

    useEffect(() => {
        if (bottomRef.current) {
            bottomRef.current.scrollIntoView({ behavior: 'smooth' })
        }
    }, [data.length])

    if (data.length === 0) {
        return (
            <div style={{
                color: '#8b949e',
                textAlign: 'center',
                paddingTop: '20px',
                fontSize: '12px',
            }}>
                <Search size={24} color="#8b949e" />
                <br />
                Chưa có truy vấn DNS nào...
                <br />
                <span style={{ fontSize: '10px', color: '#484f58' }}>
                    Hãy mở trình duyệt và truy cập một trang web
                </span>
            </div>
        )
    }

    return (
        <div style={{
            maxHeight: '220px',
            overflowY: 'auto',
            fontSize: '11px',
            fontFamily: 'monospace',
        }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
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
                    </tr>
                </thead>
                <tbody>
                    {data.map((entry, index) => (
                        <tr 
                            key={index} 
                            style={{
                                borderBottom: '1px solid #21262d',
                                transition: 'background 0.2s',
                            }}
                            onMouseEnter={(e) => e.currentTarget.style.background = '#161b22'}
                            onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                        >
                            <td style={{ ...tdStyle, color: '#8b949e', width: '90px' }}>
                                {entry.time}
                            </td>
                            <td style={{ ...tdStyle, color: '#58a6ff', width: '120px' }}>
                                {entry.src_ip}
                            </td>
                            <td style={{ ...tdStyle, color: '#e6edf3' }}>
                                <span  
                                    style={{ cursor: 'pointer' }}
                                    title="Click để copy tên miền"
                                    onClick={() => {
                                        if (navigator.clipboard) {
                                            navigator.clipboard.writeText(entry.domain)
                                        }
                                    }}
                                >
                                    {entry.domain}
                                    <span style={{ 
                                        marginLeft: '6px', 
                                        opacity: 0.6,
                                        display: 'inline-flex',
                                        alignItems: 'center'
                                    }}>
                                        <Copy size={12} />
                                    </span>
                                </span>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
            <div ref={bottomRef} />
        </div>
    )
})

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

export default DnsTimelineChart
