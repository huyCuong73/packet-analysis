import { useEffect, useState } from 'react';
import axios from 'axios';
import DetailSection from './DetailSection';
import DetailField from './DetailField';
import { Package, Loader, AlertTriangle } from 'lucide-react';
import '../styles/_detail.scss';

function PacketDetail({ packetId }) {
    const [detail, setDetail] = useState(null);
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        if (!packetId) return;

        setLoading(true);
        axios
            .get(`http://localhost:5000/api/packets/${packetId}`)
            .then((res) => setDetail(res.data))
            .catch((err) => console.error(err))
            .finally(() => setLoading(false));
    }, [packetId]);

    const eth = detail?.ethernet || {};
    const ip = detail?.ip || {};
    const tr = detail?.transport || {};
    const app = detail?.app_layer || {};
    const pay = detail?.payload || {};

    const hasData = !!detail && !!packetId && !loading;

    return (
        <div className="detail-panel">
            <div className="detail-panel__title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {loading
                    ? <><Loader size={18} className="spin" /> Loading...</>
                    : hasData
                      ? <><Package size={18} /> Packet Details #{packetId} — {detail.summary}</>
                      : <><Package size={18} /> Packet Details</>}
            </div>

            <div className="detail-panel__content">
              
                {!hasData && !loading && (
                    <div className="detail-panel__placeholder">
                        Click a packet to view details
                    </div>
                )}

                {loading && (
                    <div className="detail-panel__skeleton">
                        <div className="skeleton-line skeleton-line--w80" />
                        <div className="skeleton-line skeleton-line--w60" />
                        <div className="skeleton-line skeleton-line--w90" />
                        <div className="skeleton-line skeleton-line--w50" />
                        <div className="skeleton-line skeleton-line--w70" />
                        <div className="skeleton-line skeleton-line--w80" />
                    </div>
                )}

                {hasData && (
                    <>
                    {eth.src_mac && (
                        <DetailSection title="Ethernet Header (Data Link Layer)">
                            <DetailField label="Source MAC" value={eth.src_mac} />
                            <DetailField label="Destination MAC" value={eth.dst_mac} />
                            <DetailField
                                label="EtherType"
                                value={`${eth.ethertype} (${eth.ethertype_name})`}
                            />
                        </DetailSection>
                    )}

                    {ip.src_ip && (
                        <DetailSection title="IP Header (Network Layer)">
                            <DetailField label="Version" value={`IPv${ip.version}`} />
                            <DetailField
                                label="Header Length"
                                value={`${ip.ihl} bytes`}
                            />
                            <DetailField
                                label="Total Length"
                                value={`${ip.total_length} bytes`}
                            />
                            <DetailField
                                label="TTL"
                                value={`${ip.ttl} (${ip.os_guess})`}
                                highlight={ip.ttl <= 10 ? 'danger' : 'ok'}
                            />
                            <DetailField
                                label="Protocol"
                                value={`${ip.protocol} (${ip.protocol_name})`}
                            />
                            <DetailField label="Checksum" value={ip.checksum} />
                            <DetailField label="Source IP" value={ip.src_ip} />
                            <DetailField label="Destination IP" value={ip.dst_ip} />
                            <DetailField label="Type of Service" value={ip.tos} />
                        </DetailSection>
                    )}

                    {detail.transport_proto === 'TCP' && tr.src_port && (
                        <DetailSection title="TCP Header (Transport Layer)">
                            <DetailField label="Source Port" value={tr.src_port} />
                            <DetailField
                                label="Destination Port"
                                value={`${tr.dst_port} (${tr.service})`}
                            />
                            <DetailField label="Sequence Number" value={tr.seq} />
                            <DetailField label="Ack Number" value={tr.ack} />
                            <DetailField
                                label="Data Offset"
                                value={`${tr.data_offset} bytes`}
                            />
                            <DetailField
                                label="Flags"
                                value={tr.flags_active?.join(', ') || '—'}
                                highlight={
                                    tr.flags_active?.includes('RST')
                                        ? 'danger'
                                        : tr.flags_active?.includes('SYN')
                                          ? 'warn'
                                          : 'ok'
                                }
                            />
                            <DetailField label="Window Size" value={tr.window_size} />
                            <DetailField label="Checksum" value={tr.checksum} />
                        </DetailSection>
                    )}

                    {detail.transport_proto === 'UDP' && tr.src_port && (
                        <DetailSection title="UDP Header (Transport Layer)">
                            <DetailField label="Source Port" value={tr.src_port} />
                            <DetailField
                                label="Destination Port"
                                value={`${tr.dst_port} (${tr.service})`}
                            />
                            <DetailField label="Length" value={`${tr.length} bytes`} />
                            <DetailField label="Checksum" value={tr.checksum} />
                        </DetailSection>
                    )}

                    {app.dns && (
                        <DetailSection title="DNS (Application Layer)">
                            <DetailField label="Type" value={app.dns.type} />
                            <DetailField label="Transaction" value={app.dns.tx_id} />
                            {app.dns.queries?.map((q, i) => (
                                <DetailField
                                    key={i}
                                    label={`Query ${i + 1}`}
                                    value={`${q.name} (${q.type})`}
                                    highlight={app.dns.is_suspicious ? 'danger' : ''}
                                />
                            ))}
                            {app.dns.is_suspicious && (
                                <DetailField
                                    label={<span style={{display: 'flex', alignItems: 'center', gap: '4px'}}><AlertTriangle size={14} /> Warning</span>}
                                    value={app.dns.suspicious_reason}
                                    highlight="danger"
                                />
                            )}
                        </DetailSection>
                    )}

                    {app.http && (
                        <DetailSection title="HTTP (Application Layer)">
                            {app.http.direction === 'request' ? (
                                <>
                                    <DetailField
                                        label="Method"
                                        value={app.http.method}
                                    />
                                    <DetailField label="URI" value={app.http.uri} />
                                    <DetailField label="Host" value={app.http.host} />
                                    <DetailField
                                        label="Version"
                                        value={app.http.version}
                                    />
                                    {app.http.credentials_found && (
                                        <DetailField
                                            label={<span style={{display: 'flex', alignItems: 'center', gap: '4px'}}><AlertTriangle size={14} /> Credentials</span>}
                                            value={app.http.credentials
                                                .map((c) => `${c.type}: ${c.value}`)
                                                .join(' | ')}
                                            highlight="danger"
                                        />
                                    )}
                                </>
                            ) : (
                                <>
                                    <DetailField
                                        label="Status"
                                        value={`${app.http.status_code} ${app.http.status_text}`}
                                        highlight={
                                            app.http.status_code >= 400
                                                ? 'danger'
                                                : 'ok'
                                        }
                                    />
                                    <DetailField
                                        label="Version"
                                        value={app.http.version}
                                    />
                                </>
                            )}
                        </DetailSection>
                    )}

                    {pay.hex_dump && (
                        <DetailSection title="Payload (Hex Dump)" defaultOpen={false}>
                            <pre className="detail-panel__hexdump">{pay.hex_dump}</pre>
                        </DetailSection>
                    )}
                </>
            )}
            </div>
        </div>
    );
}

export default PacketDetail;
