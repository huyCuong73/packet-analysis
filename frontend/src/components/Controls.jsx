import { useState, useRef } from 'react'
import InterfaceSelector from './InterfaceSelector'
import { useInterfaces } from '../hooks/useInterfaces'
import { Play, Square, Snail, Zap, Rocket, PlaySquare, FolderOpen, X, Trash2, FileText } from 'lucide-react'

function Controls({
	isConnected, isCapturing, packetCount,
	onStart, onStop, onClear,
	currentSessionName,
	onUploadPcap, isPcapMode, onExitPcap,
	onReplay,
	isReplaying,
	replayProgress
}) {
	const [filter, setFilter] = useState('')
	const [speed, setSpeed] = useState('1')
	const replayInputRef = useRef()

	const {
		interfaces, selectedInterface,
		setSelectedInterface, loading
	} = useInterfaces()

	const handleStart = () => {
		const iface = selectedInterface === 'auto' ? '' : selectedInterface
		onStart(filter, '', iface)
	}


	const handleFileSelected = (e) => {
		const file = e.target.files[0]
		if (!file) return
		onReplay(file, parseFloat(speed))
		e.target.value = ''
	}

	const isBusy = isCapturing || isReplaying || isPcapMode

	return (
		<div className="controls">


			<InterfaceSelector
				interfaces={interfaces}
				value={selectedInterface}
				onChange={setSelectedInterface}
				disabled={isBusy}
				loading={loading}
			/>

			<span className="controls__label">Filter:</span>
			<input
				className="controls__filter-input"
				placeholder='e.g. tcp port 80'
				value={filter}
				onChange={e => setFilter(e.target.value)}
				onKeyDown={e => {
					if (e.key === 'Enter' && !isBusy && isConnected)
						handleStart()
				}}
				disabled={isBusy}
			/>


			<button className="btn btn--start"
				onClick={handleStart}
				disabled={!isConnected || isBusy}
				style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
				<Play size={14} /> Start
			</button>


			<button className="btn btn--stop"
				onClick={onStop}
				disabled={!isCapturing && !isReplaying}
				style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
				<Square size={14} /> Stop
			</button>


			<select
				className="speed-select"
				value={speed}
				onChange={e => setSpeed(e.target.value)}
				disabled={isBusy}
				title="Replay speed"
			>
				<option value="0.5">0.5x</option>
				<option value="1">1x</option>
				<option value="2">2x</option>
				<option value="5">5x</option>
				<option value="10">10x</option>
				<option value="20">20x</option>
			</select>


			<button
				className="btn btn--clear"
				onClick={() => replayInputRef.current.click()}
				disabled={isBusy}
				title="Select .pcap file to replay"
				style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
			>
				<PlaySquare size={14} /> Replay .pcap
			</button>


			<input
				ref={replayInputRef}
				type="file"
				accept=".pcap,.pcapng"
				style={{ display: 'none' }}
				onChange={handleFileSelected}
			/>


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


			<button className="btn btn--clear"
				onClick={onUploadPcap}
				disabled={isBusy}
				style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
				<FolderOpen size={14} /> Open .pcap
			</button>

			{isPcapMode && (
				<button className="btn btn--stop"
					onClick={onExitPcap}
					style={{ fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
					<X size={14} /> Close file
				</button>
			)}


			<button className="btn btn--clear"
				onClick={onClear}
				disabled={isBusy}
				style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
				<Trash2 size={14} /> Clear
			</button>


			<span className="controls__count" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
				{isReplaying && (
					<span style={{ color: '#d2a8ff', marginRight: '8px', display: 'flex', alignItems: 'center', gap: '4px' }}>
						<PlaySquare size={14} /> Replaying...
					</span>
				)}
				{isCapturing && currentSessionName && (
					<span style={{ color: '#58a6ff', marginRight: '8px', display: 'flex', alignItems: 'center', gap: '4px' }}>
						<FileText size={14} /> {currentSessionName}
					</span>
				)}
				{isBusy ? <><Zap size={14} /> {packetCount} packets</> : `${packetCount} packets`}
			</span>

		</div>
	)
}

export default Controls