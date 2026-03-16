import { useState, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useFrontendStats } from '../hooks/useFrontendStats';
import Controls from '../components/Controls';
import FilterBar from '../components/FilterBar';
import PacketTable from '../components/PacketTable';
import PacketDetail from '../components/PacketDetail';
import ProtocolChart from '../components/ProtocolChart';
import TopIPChart from '../components/TopIPChart';
import TimeChart from '../components/TimeChart';
import PcapUploader from '../components/PcapUploader';
import axios from 'axios';
import '../styles/_charts.scss';
import '../styles/_layout.scss';

function Dashboard({ socket }) {
    const {
        isConnected,
        isCapturing,
        packets,
        startCapture,
        stopCapture,
        clearPackets,
        currentSessionId,
        currentSessionName,
    } = socket;

    const [searchParams] = useSearchParams();
    const viewSessionId = searchParams.get('session_id')
        ? parseInt(searchParams.get('session_id'))
        : null;

    // Packets lịch sử khi xem lại phiên cũ
    const [historicalPackets, setHistoricalPackets] = useState([]);

    useEffect(() => {
        if (!viewSessionId) {
            setHistoricalPackets([]);
            return;
        }
        // Gọi API lấy packets của phiên cũ
        axios
            .get(
                `http://localhost:5000/api/packets?session_id=${viewSessionId}&limit=1000`
            )
            .then((res) => setHistoricalPackets(res.data))
            .catch((err) => console.error(err));
    }, [viewSessionId]);

    const [selectedId, setSelectedId] = useState(null);
    const handleClear = () => {
        clearPackets();
        setSelectedId(null);
    };

    // State cho pcap upload
    const [pcapPackets, setPcapPackets] = useState([]);
    const [pcapSessionName, setPcapSessionName] = useState('');
    const [isPcapMode, setIsPcapMode] = useState(false);
    const [showUploader, setShowUploader] = useState(false);

    const handlePcapLoaded = ({ sessionId, sessionName, packets, total }) => {
        setPcapPackets(packets);
        setPcapSessionName(sessionName);
        setIsPcapMode(true);
        setShowUploader(false);
        setSelectedId(null);
    };

    const handleExitPcap = () => {
        setPcapPackets([]);
        setPcapSessionName('');
        setIsPcapMode(false);
    };

    // Quyết định dùng packets nào để tính stats
    const activePackets = isPcapMode
        ? pcapPackets
        : viewSessionId
          ? historicalPackets
          : packets;

    // ── Bộ lọc phía frontend ────────────────────────────────────────
    const [filters, setFilters] = useState({
        search: '',
        protocol: '',
        port: '',
    });

    const filteredPackets = useMemo(() => {
        const { search, protocol, port } = filters;
        if (!search && !protocol && !port) return activePackets;

        return activePackets.filter((pkt) => {
            // Lọc theo protocol
            if (protocol && pkt.protocol !== protocol) return false;

            // Lọc theo IP (src hoặc dst, match partial)
            if (search) {
                const q = search.toLowerCase();
                const srcMatch = (pkt.src_ip || '').toLowerCase().includes(q);
                const dstMatch = (pkt.dst_ip || '').toLowerCase().includes(q);
                if (!srcMatch && !dstMatch) return false;
            }

            // Lọc theo port (src hoặc dst)
            if (port) {
                const p = parseInt(port);
                if (!isNaN(p) && pkt.src_port !== p && pkt.dst_port !== p)
                    return false;
            }

            return true;
        });
    }, [activePackets, filters]);

    // Charts dùng dữ liệu đã lọc
    const { protocolStats, topIPs, timeStats } =
        useFrontendStats(filteredPackets);

    return (
        <div className="page-content">
            <Controls
                isConnected={isConnected}
                isCapturing={isCapturing}
                packetCount={packets.length}
                onStart={startCapture}
                onStop={stopCapture}
                onClear={handleClear}
                currentSessionName={currentSessionName}
                onUploadPcap={() => setShowUploader((prev) => !prev)}
                isPcapMode={isPcapMode}
                onExitPcap={handleExitPcap}
            />

            <main className="main-content">
                {showUploader && <PcapUploader onLoaded={handlePcapLoaded} />}

                {isPcapMode && (
                    <div
                        style={{
                            background: 'rgba(63, 185, 80, 0.1)',
                            border: '1px solid #3fb950',
                            borderRadius: '8px',
                            padding: '10px 16px',
                            color: '#3fb950',
                            fontSize: '13px',
                        }}
                    >
                        📂 Đang xem: <strong>{pcapSessionName}</strong> —{' '}
                        {pcapPackets.length} gói tin
                    </div>
                )}
                {/* Banner khi đang xem phiên cũ */}
                {viewSessionId && viewSessionId !== currentSessionId && (
                    <div
                        style={{
                            background: 'rgba(88,166,255,0.1)',
                            border: '1px solid #58a6ff',
                            borderRadius: '8px',
                            padding: '10px 16px',
                            color: '#58a6ff',
                            fontSize: '13px',
                        }}
                    >
                        👁 Đang xem lại phiên #{viewSessionId}— dữ liệu chỉ đọc
                    </div>
                )}

                <div className="charts-row">
                    <div className="chart-card">
                        <div className="chart-card__title">📊 Protocol</div>
                        <ProtocolChart data={protocolStats} />
                    </div>
                    <div className="chart-card">
                        <div className="chart-card__title">🌐 Top IP</div>
                        <TopIPChart data={topIPs} />
                    </div>
                    <div className="chart-card">
                        <div className="chart-card__title">
                            📈 Traffic theo thời gian
                        </div>
                        <TimeChart data={timeStats} />
                    </div>
                </div>

                <div className="packet-row">
                    <div className="table-section">
                        <div className="table-section__header">📡 Packet List</div>
                        <FilterBar
                            totalCount={activePackets.length}
                            filteredCount={filteredPackets.length}
                            onFilterChange={setFilters}
                        />
                        <PacketTable
                            packets={filteredPackets}
                            selectedId={selectedId}
                            onSelectPacket={setSelectedId}
                        />
                    </div>

                    <PacketDetail packetId={selectedId} />
                </div>
            </main>
        </div>
    );
}

export default Dashboard;
