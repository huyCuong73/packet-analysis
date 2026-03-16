import ProtocolBadge from './ProtocolBadge';
import '../styles/_table.scss';

function PacketTable({ packets, selectedId, onSelectPacket }) {
    return (
        <div style={{ overflowY: 'auto', maxHeight: '450px' }}>
            <table className="packet-table">
                {/* Header */}
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

                {/* Các dòng gói tin */}
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
                            <td>{packet.src_ip || '—'}</td>
                            <td>{packet.dst_ip || '—'}</td>
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

                    {/* Khi chưa có gói tin nào */}
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
                                Nhấn "Bắt đầu" để bắt gói tin...
                            </td>
                        </tr>
                    )}
                </tbody>
            </table>
        </div>
    );
}

export default PacketTable;
