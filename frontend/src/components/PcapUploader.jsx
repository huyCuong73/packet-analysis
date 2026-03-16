import { useState, useRef } from 'react';
import axios from 'axios';

function PcapUploader({ onLoaded }) {
    const [isDragOver, setIsDragOver] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [progress, setProgress] = useState(0);
    const [error, setError] = useState('');
    const inputRef = useRef();

    const handleFile = async (file) => {
        if (!file) return;

        // Kiểm tra đuôi file
        if (!file.name.endsWith('.pcap')) {
            setError('Chỉ hỗ trợ file .pcap');
            return;
        }

        setError('');
        setIsLoading(true);
        setProgress(10);

        const formData = new FormData();
        formData.append('file', file);

        try {
            setProgress(40);
            const res = await axios.post(
                'http://localhost:5000/api/upload-pcap',
                formData,
                { headers: { 'Content-Type': 'multipart/form-data' } }
            );
            setProgress(100);

            // Gọi callback để Dashboard nhận dữ liệu
            onLoaded({
                sessionId: res.data.session_id,
                sessionName: res.data.session_name,
                packets: res.data.packets,
                total: res.data.total_packets,
            });
        } catch (err) {
            setError(err.response?.data?.error || 'Lỗi khi xử lý file');
        } finally {
            setIsLoading(false);
            setTimeout(() => setProgress(0), 1000);
        }
    };

    // Kéo thả file
    const handleDrop = (e) => {
        e.preventDefault();
        setIsDragOver(false);
        const file = e.dataTransfer.files[0];
        handleFile(file);
    };

    return (
        <div>
            {/* Vùng kéo thả */}
            <div
                className={`upload-zone ${isDragOver ? 'upload-zone--dragover' : ''}`}
                onClick={() => inputRef.current.click()}
                onDragOver={(e) => {
                    e.preventDefault();
                    setIsDragOver(true);
                }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={handleDrop}
            >
                <div className="upload-zone__icon">
                    {isLoading ? '⏳' : '📂'}
                </div>
                <div className="upload-zone__text">
                    {isLoading
                        ? 'Đang xử lý file...'
                        : 'Kéo thả file .pcap vào đây hoặc click để chọn'}
                </div>
                <div className="upload-zone__hint">Hỗ trợ định dạng: .pcap</div>

                {/* Input ẩn */}
                <input
                    ref={inputRef}
                    type="file"
                    accept=".pcap"
                    style={{ display: 'none' }}
                    onChange={(e) => handleFile(e.target.files[0])}
                />
            </div>

            {/* Progress bar */}
            {progress > 0 && (
                <div className="upload-progress">
                    <div
                        className="upload-progress__bar"
                        style={{ width: `${progress}%` }}
                    />
                </div>
            )}

            {/* Thông báo lỗi */}
            {error && (
                <div
                    style={{
                        marginTop: '8px',
                        color: '#f85149',
                        fontSize: '12px',
                    }}
                >
                    ⚠️ {error}
                </div>
            )}
        </div>
    );
}

export default PcapUploader;
