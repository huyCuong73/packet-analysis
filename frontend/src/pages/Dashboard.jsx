import { useState, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useFrontendStats } from '../hooks/useFrontendStats';
import BandwidthChart from '../components/BandwidthChart';
import Controls from '../components/Controls';
import FilterBar from '../components/FilterBar';
import PacketTable from '../components/PacketTable';
import PacketDetail from '../components/PacketDetail';
import ProtocolChart from '../components/ProtocolChart';
import TopIPChart from '../components/TopIPChart';
import TimeChart from '../components/TimeChart';
import TrafficLocationChart from '../components/TrafficLocationChart';
import PortActivityChart from '../components/PortActivityChart';
import PcapUploader from '../components/PcapUploader';
import axios from 'axios';
import { Rocket, BarChart2, Globe, LineChart, Home, Activity, FileText, Eye, FolderOpen } from 'lucide-react';
import '../styles/_charts.scss';
import '../styles/_layout.scss';

function Dashboard({ socket }) {
	const {
		isConnected,
		isCapturing,
		packets,
		startCapture,
		stopCapture,
		currentSessionId,
		currentSessionName,
		dnsMap,
		clearPackets,
		isReplaying,
		setIsReplaying,
		replayProgress,
	} = socket;

	const [searchParams] = useSearchParams();
	const viewSessionId = searchParams.get('session_id')
		? parseInt(searchParams.get('session_id'))
		: null;

	const [historicalPackets, setHistoricalPackets] = useState([]);

	useEffect(() => {
		if (!viewSessionId) {
			setHistoricalPackets([]);
			return;
		}
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

	const activePackets = isPcapMode
		? pcapPackets
		: viewSessionId
			? historicalPackets
			: packets;

	const [filters, setFilters] = useState({
		search: '',
		protocol: '',
		port: '',
	});

	const filteredPackets = useMemo(() => {
		const { search, protocol, port } = filters;
		if (!search && !protocol && !port) return activePackets;

		return activePackets.filter((pkt) => {
			if (protocol && pkt.protocol !== protocol) return false;

			if (search) {
				const q = search.toLowerCase();
				const srcMatch = (pkt.src_ip || '').toLowerCase().includes(q);
				const dstMatch = (pkt.dst_ip || '').toLowerCase().includes(q);
				if (!srcMatch && !dstMatch) return false;
			}

			if (port) {
				const p = parseInt(port);
				if (!isNaN(p) && pkt.src_port !== p && pkt.dst_port !== p)
					return false;
			}

			return true;
		});
	}, [activePackets, filters]);

	const handleReplay = async (file, speed) => {
		clearPackets()
		setSelectedId(null)

		const formData = new FormData()
		formData.append('file', file)
		formData.append('speed', speed)

		try {
			await axios.post(
				'http://localhost:5000/api/replay-pcap',
				formData,
				{ headers: { 'Content-Type': 'multipart/form-data' } }
			)
			setIsReplaying(true) 
		} catch (err) {
			console.error('Replay error:', err)
		}
	}

	const { protocolStats, topIPs, timeStats, topTalkers, trafficLocation, portActivity, credentialsList } = useFrontendStats(filteredPackets);

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
				onReplay={handleReplay}           
				isReplaying={isReplaying}         
				replayProgress={replayProgress}
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
							display: 'flex',
							alignItems: 'center',
							gap: '6px'
						}}
					>
						<FolderOpen size={16} /> Đang xem: <strong>{pcapSessionName}</strong> —{' '}
						{pcapPackets.length} gói tin
					</div>
				)}
				{viewSessionId && (
					<div
						style={{
							background: 'rgba(88,166,255,0.1)',
							border: '1px solid #58a6ff',
							borderRadius: '8px',
							padding: '10px 16px',
							color: '#58a6ff',
							fontSize: '13px',
							display: 'flex',
							alignItems: 'center',
							gap: '6px'
						}}
					>
						<Eye size={16} /> Đang xem lại phiên #{viewSessionId}— dữ liệu chỉ đọc
					</div>
				)}

				<div className="charts-row">
					<div className="chart-card">
						<div className="chart-card__title" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
							<Rocket size={16} color="#d2a8ff" /> Top Talkers
							<span style={{
								fontSize: '10px',
								color: '#8b949e',
								fontWeight: 400,
								marginLeft: '6px'
							}}>
								(băng thông tích lũy)
							</span>
						</div>
						<BandwidthChart data={topTalkers} dnsMap={dnsMap} />
					</div>
					<div className="chart-card">
						<div className="chart-card__title" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><BarChart2 size={16} color="#58a6ff" /> Protocol</div>
						<ProtocolChart data={protocolStats} />
					</div>
					<div className="chart-card">
						<div className="chart-card__title" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><Globe size={16} color="#3fb950" /> Top IP</div>
						<TopIPChart data={topIPs} dnsMap={dnsMap} />
					</div>
					<div className="chart-card">
						<div className="chart-card__title" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
							<LineChart size={16} color="#e3b341" /> Traffic theo thời gian
						</div>
						<TimeChart data={timeStats} />
					</div>
					<div className="chart-card">
						<div className="chart-card__title" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><Home size={16} color="#ffa657" /> Nội bộ vs Internet</div>
						<TrafficLocationChart data={trafficLocation} />
					</div>
					<div className="chart-card">
						<div className="chart-card__title" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><Activity size={16} color="#f85149" /> Hoạt động Port theo thời gian</div>
						<PortActivityChart data={portActivity} />
					</div>
				</div>

				<div className="packet-row">
					<div className="table-section">
						<div className="table-section__header" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><FileText size={16} color="#8b949e" /> Packet List</div>
						<FilterBar
							totalCount={activePackets.length}
							filteredCount={filteredPackets.length}
							onFilterChange={setFilters}
						/>
						<PacketTable
							packets={filteredPackets}
							onSelectPacket={setSelectedId}
							selectedId={selectedId}
							dnsMap={dnsMap}
						/>
					</div>

					<PacketDetail packetId={selectedId} />
				</div>
			</main>
		</div>
	);
}

export default Dashboard;
