import ProtocolBadge from './ProtocolBadge';
import { Copy } from 'lucide-react';
import '../styles/_table.scss';

function PacketTable({ packets, selectedId, onSelectPacket, dnsMap = {} }) {
    const handleCopyDomain = (e, domain) => {
        e.stopPropagation();
        if (domain && navigator.clipboard) {
            navigator.clipboard.writeText(domain);
        }
    };

    return (
        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>
            <table className="packet-table">
                <thead className="packet-table__header">
                    <tr>
                        <th>#</th>
                        <th>Time</th>
                        <th>Protocol</th>
                        <th>Src IP</th>
                        <th>Dst IP</th>
                        <th>Sport</th>
                        <th>Dport</th>
                        <th>Len</th>
                        <th>TTL</th>
                        <th>Flags</th>
                    </tr>
                </thead>

                <tbody>
                    {packets.map((packet) => (
                        <tr
                            key={packet.id}
                            className={`packet-table__row ${
                                selectedId === packet.id
                                    ? 'packet-table__row--selected'
                                    : ''
                            }`}
                            onClick={() => onSelectPacket(packet.id)}
                        >
                            <td>{packet.id}</td>
                            <td>{packet.time}</td>
                            <td>
                                <ProtocolBadge protocol={packet.protocol} />
                            </td>
                            <td title={packet.src_ip}>
                                {dnsMap[packet.src_ip] ? (
                                    <>
                                        {packet.src_ip} ({dnsMap[packet.src_ip]})
                                        <span 
                                            title="Copy Domain" 
                                            onClick={(e) => handleCopyDomain(e, dnsMap[packet.src_ip])}
                                            style={{ cursor: 'pointer', marginLeft: '6px', opacity: 0.5, display: 'inline-flex', alignItems: 'center' }}
                                        >
                                            <Copy size={12} />
                                        </span>
                                    </>
                                ) : packet.src_ip || '—'}
                            </td>
                            <td title={packet.dst_ip}>
                                {dnsMap[packet.dst_ip] ? (
                                    <>
                                        {packet.dst_ip} ({dnsMap[packet.dst_ip]})
                                        <span 
                                            title="Copy Domain" 
                                            onClick={(e) => handleCopyDomain(e, dnsMap[packet.dst_ip])}
                                            style={{ cursor: 'pointer', marginLeft: '6px', opacity: 0.5, display: 'inline-flex', alignItems: 'center' }}
                                        >
                                            <Copy size={12} />
                                        </span>
                                    </>
                                ) : packet.dst_ip || '—'}
                            </td>
                            <td>{packet.src_port || '—'}</td>
                            <td>{packet.dst_port || '—'}</td>
                            <td>{packet.length || '—'}</td>
                            <td>{packet.ttl || '—'}</td>
                            <td
                                style={{
                                    fontFamily: 'monospace',
                                    fontSize: '11px',
                                }}
                            >
                                {Array.isArray(packet.flags)
                                    ? packet.flags.join(',') || '—'
                                    : packet.flags || '—'}
                            </td>
                        </tr>
                    ))}

                    {packets.length === 0 && (
                        <tr>
                            <td
                                colSpan={10}
                                style={{
                                    textAlign: 'center',
                                    padding: '40px',
                                    color: '#8b949e',
                                }}
                            >
                                Click "Start" to capture packets...
                            </td>
                        </tr>
                    )}
                </tbody>
            </table>
        </div>
    );
}

export default PacketTable;
