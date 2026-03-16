import { useState } from 'react';
import InterfaceSelector from './InterfaceSelector';
import { useInterfaces } from '../hooks/useInterfaces';

function Controls({
    isConnected,
    isCapturing,
    packetCount,
    onStart,
    onStop,
    onClear,
    currentSessionName,
    onUploadPcap,
    isPcapMode,
    onExitPcap,
}) {
    const [filter, setFilter] = useState('');
    const { interfaces, selectedInterface, setSelectedInterface, loading } =
        useInterfaces();

    const handleStart = () => {
        // Truyền interface vào startCapture
        // 'auto' → truyền chuỗi rỗng → server hiểu là None
        const iface = selectedInterface === 'auto' ? '' : selectedInterface;
        onStart(filter, '', iface);
    };

    return (
        <div className="controls">
            {/* Chọn interface */}
            <InterfaceSelector
                interfaces={interfaces}
                value={selectedInterface}
                onChange={setSelectedInterface}
                disabled={isCapturing || isPcapMode}
                loading={loading}
            />

            <span className="controls__label">Filter:</span>
            <input
                className="controls__filter-input"
                placeholder="vd: tcp port 80"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                onKeyDown={(e) => {
                    if (e.key === 'Enter' && !isCapturing && isConnected)
                        handleStart();
                }}
                disabled={isCapturing || isPcapMode}
            />

            <button
                className="btn btn--start"
                onClick={handleStart}
                disabled={!isConnected || isCapturing || isPcapMode}
            >
                ▶ Bắt đầu
            </button>

            <button
                className="btn btn--stop"
                onClick={onStop}
                disabled={!isCapturing}
            >
                ⏹ Dừng
            </button>

            <button
                className="btn btn--clear"
                onClick={onUploadPcap}
                disabled={isCapturing}
            >
                📂 Mở .pcap
            </button>

            {isPcapMode && (
                <button
                    className="btn btn--stop"
                    onClick={onExitPcap}
                    style={{ fontSize: '12px' }}
                >
                    ✕ Đóng file
                </button>
            )}

            <button
                className="btn btn--clear"
                onClick={onClear}
                disabled={isCapturing}
            >
                🗑 Xóa
            </button>

            <span className="controls__count">
                {isCapturing && currentSessionName && (
                    <span style={{ color: '#58a6ff', marginRight: '8px' }}>
                        📋 {currentSessionName}
                    </span>
                )}
                {isCapturing
                    ? `⚡ ${packetCount} gói tin`
                    : `${packetCount} gói tin`}
            </span>
        </div>
    );
}

export default Controls;
