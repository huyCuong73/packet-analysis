import React, { memo } from 'react'
import { CheckCircle, Clock } from 'lucide-react'

const CredentialsTable = memo(function CredentialsTable({ data = [], onSelectPacket }) {
    if (data.length === 0) {
        return (
            <div style={{
                color: '#8b949e',
                textAlign: 'center',
                paddingTop: '20px',
                fontSize: '12px',
            }}>
                <span style={{ fontSize: '20px' }}><CheckCircle size={24} color="#3fb950" /></span>
                <br />
                No credential leaks detected
            </div>
        )
    }

    return (
        <div style={{
            maxHeight: '200px',
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
                        <th style={thStyle}><div style={{display:'flex', alignItems:'center', gap:'4px'}}><Clock size={12}/> Time</div></th>
                        <th style={thStyle}>Attacker (Source)</th>
                        <th style={thStyle}>Victim (Destination)</th>
                        <th style={thStyle}>Leaked Info</th>
                        <th style={thStyle}></th>
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
                            <td style={{ ...tdStyle, color: '#8b949e', width: '80px' }}>
                                {entry.time}
                            </td>
                            <td style={{ ...tdStyle, color: '#58a6ff', width: '110px' }}>
                                {entry.src_ip}
                            </td>
                            <td style={{ ...tdStyle, color: '#f85149', width: '110px' }}>
                                {entry.dst_ip}
                            </td>
                            <td style={{ ...tdStyle, color: '#e6edf3' }}>
                                {entry.credentials.map((c, i) => (
                                    <div key={i} style={{ marginBottom: i < entry.credentials.length - 1 ? '4px' : 0 }}>
                                        <span style={{ color: '#e3b341', fontWeight: 600 }}>{c.type}:</span>{' '}
                                        <span style={{ 
                                            background: 'rgba(248,81,73,0.15)', 
                                            padding: '2px 4px', 
                                            borderRadius: '3px',
                                            color: '#f85149',
                                            fontWeight: 'bold'
                                        }}>
                                            {c.value}
                                        </span>
                                    </div>
                                ))}
                            </td>
                            <td style={{ ...tdStyle, textAlign: 'right' }}>
                                <button 
                                    className="btn btn--clear" 
                                    style={{ padding: '2px 6px', fontSize: '10px' }}
                                    onClick={() => onSelectPacket(entry.id)}
                                >
                                    View packet
                                </button>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
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
    padding: '8px 8px',
    verticalAlign: 'top',
}

export default CredentialsTable
