import { useState, useRef } from 'react';
import axios from 'axios';
import { FolderOpen, Loader, AlertTriangle } from 'lucide-react';

function PcapUploader({ onLoaded }) {
    const [isDragOver, setIsDragOver] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [progress, setProgress] = useState(0);
    const [error, setError] = useState('');
    const inputRef = useRef();

    const handleFile = async (file) => {
        if (!file) return;

        if (!file.name.endsWith('.pcap') && !file.name.endsWith('.pcapng')) {
            setError('Only .pcap or .pcapng files are supported');
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

            onLoaded({
                sessionId: res.data.session_id,
                sessionName: res.data.session_name,
                packets: res.data.packets,
                total: res.data.total_packets,
            });
        } catch (err) {
            setError(err.response?.data?.error || 'Error processing file');
        } finally {
            setIsLoading(false);
            setTimeout(() => setProgress(0), 1000);
        }
    };

    const handleDrop = (e) => {
        e.preventDefault();
        setIsDragOver(false);
        const file = e.dataTransfer.files[0];
        handleFile(file);
    };

    return (
        <div>
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
                    {isLoading ? <Loader size={32} className="spin" /> : <FolderOpen size={32} />}
                </div>
                <div className="upload-zone__text">
                    {isLoading
                        ? 'Processing file...'
                        : 'Drag and drop a .pcap file here or click to select'}
                </div>
                <div className="upload-zone__hint">Supported format: .pcap</div>

                <input
                    ref={inputRef}
                    type="file"
                    accept=".pcap,.pcapng"
                    style={{ display: 'none' }}
                    onChange={(e) => handleFile(e.target.files[0])}
                />
            </div>

            {progress > 0 && (
                <div className="upload-progress">
                    <div
                        className="upload-progress__bar"
                        style={{ width: `${progress}%` }}
                    />
                </div>
            )}

            {error && (
                <div
                    style={{
                        marginTop: '8px',
                        color: '#f85149',
                        fontSize: '12px',
                    }}
                >
                    <AlertTriangle size={14} style={{ verticalAlign: 'middle', marginRight: '4px' }} /> {error}
                </div>
            )}
        </div>
    );
}

export default PcapUploader;
