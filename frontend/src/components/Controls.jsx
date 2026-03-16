import { useState, useRef } from 'react'
import InterfaceSelector from './InterfaceSelector'
import { useInterfaces } from '../hooks/useInterfaces'
import { Play, Square, Snail, Zap, Rocket, PlaySquare, FolderOpen, X, Trash2, FileText } from 'lucide-react'

function Controls({
	isConnected, isCapturing, packetCount,
	onStart, onStop, onClear,
	currentSessionName,
	onUploadPcap, isPcapMode, onExitPcap,
	// ── Props mới cho replay ──
	onReplay,
	isReplaying,
	replayProgress
}) {
	const [filter, setFilter] = useState('')
	const [speed, setSpeed] = useState('1')
	const replayInputRef = useRef()   // input file ẩn

	const {
		interfaces, selectedInterface,
		setSelectedInterface, loading
	} = useInterfaces()

	const handleStart = () => {
		const iface = selectedInterface === 'auto' ? '' : selectedInterface
		onStart(filter, '', iface)
	}

	// Khi chọn file xong → gửi lên backend
	const handleFileSelected = (e) => {
		const file = e.target.files[0]
		if (!file) return
		onReplay(file, parseFloat(speed))
		// Reset input để có thể chọn lại cùng file
		e.target.value = ''
	}

	const isBusy = isCapturing || isReplaying || isPcapMode

	return (
		<div className="controls">

			{/* Interface selector */}
			<InterfaceSelector
				interfaces={interfaces}
				value={selectedInterface}
				onChange={setSelectedInterface}
				disabled={isBusy}
				loading={loading}
			/>

			{/* BPF Filter */}
			<span className="controls__label">Filter:</span>
			<input
				className="controls__filter-input"
				placeholder='vd: tcp port 80'
				value={filter}
				onChange={e => setFilter(e.target.value)}
				onKeyDown={e => {
					if (e.key === 'Enter' && !isBusy && isConnected)
						handleStart()
				}}
				disabled={isBusy}
			/>

			{/* Bắt đầu */}
			<button className="btn btn--start"
				onClick={handleStart}
				disabled={!isConnected || isBusy}
				style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
				<Play size={14} /> Bắt đầu
			</button>

			{/* Dừng */}
			<button className="btn btn--stop"
				onClick={onStop}
				disabled={!isCapturing && !isReplaying}
				style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
				<Square size={14} /> Dừng
			</button>

			{/* ── Replay section ──────────────────────────────────────── */}
			{/* Chọn tốc độ */}
			<select
				className="speed-select"
				value={speed}
				onChange={e => setSpeed(e.target.value)}
				disabled={isBusy}
				title="Tốc độ replay"
			>
				<option value="0.5">🐢 0.5x</option>
				<option value="1">▶ 1x</option>
				<option value="2">⚡ 2x</option>
				<option value="5">🚀 5x</option>
				<option value="10">⚡ 10x</option>
				<option value="20">💨 20x</option>
			</select>

			{/* Nút Replay — click → mở file picker */}
			<button
				className="btn btn--clear"
				onClick={() => replayInputRef.current.click()}
				disabled={isBusy}
				title="Chọn file .pcap để replay"
				style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
			>
				<PlaySquare size={14} /> Replay .pcap
			</button>

			{/* Input file ẩn */}
			<input
				ref={replayInputRef}
				type="file"
				accept=".pcap,.pcapng"
				style={{ display: 'none' }}
				onChange={handleFileSelected}
			/>

			{/* Progress replay */}
			{isReplaying && (
				<div style={{
					display: 'flex',
					alignItems: 'center',
					gap: '6px'
				}}>
					<div style={{
						width: '80px',
						height: '4px',
						background: '#21262d',
						borderRadius: '2px',
						overflow: 'hidden'
					}}>
						<div style={{
							width: `${replayProgress}%`,
							height: '100%',
							background: '#d2a8ff',
							transition: 'width 0.3s ease'
						}} />
					</div>
					<span style={{
						color: '#d2a8ff',
						fontSize: '11px',
						fontFamily: 'monospace'
					}}>
						{replayProgress}%
					</span>
				</div>
			)}

			{/* Mở PCAP */}
			<button className="btn btn--clear"
				onClick={onUploadPcap}
				disabled={isBusy}
				style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
				<FolderOpen size={14} /> Mở .pcap
			</button>

			{isPcapMode && (
				<button className="btn btn--stop"
					onClick={onExitPcap}
					style={{ fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
					<X size={14} /> Đóng file
				</button>
			)}

			{/* Xóa */}
			<button className="btn btn--clear"
				onClick={onClear}
				disabled={isBusy}
				style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
				<Trash2 size={14} /> Xóa
			</button>

			{/* Đếm gói tin */}
			<span className="controls__count" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
				{isReplaying && (
					<span style={{ color: '#d2a8ff', marginRight: '8px', display: 'flex', alignItems: 'center', gap: '4px' }}>
						<PlaySquare size={14} /> Đang replay...
					</span>
				)}
				{isCapturing && currentSessionName && (
					<span style={{ color: '#58a6ff', marginRight: '8px', display: 'flex', alignItems: 'center', gap: '4px' }}>
						<FileText size={14} /> {currentSessionName}
					</span>
				)}
				{isBusy ? <><Zap size={14} /> {packetCount} gói tin</> : `${packetCount} gói tin`}
			</span>

		</div>
	)
}

export default Controls