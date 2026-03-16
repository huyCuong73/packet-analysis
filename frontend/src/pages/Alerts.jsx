import { useState, useEffect } from 'react';
import axios from 'axios';
import '../styles/_alerts.scss';
import { Bell, RefreshCw, CheckCircle } from 'lucide-react';

function Alerts() {
    const [alerts, setAlerts] = useState([]);

    // Lấy danh sách alert từ backend
    const fetchAlerts = async () => {
        try {
            const res = await axios.get('http://localhost:5000/api/alerts');
            setAlerts(res.data);
        } catch (err) {
            console.error(err);
        }
    };

    useEffect(() => {
        fetchAlerts();
        // Refresh mỗi 5 giây
        const interval = setInterval(fetchAlerts, 5000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="page-content">
            <div className="alerts-page">
                {/* Tiêu đề */}
                <div style={{ marginBottom: '16px' }}>
                    <h2 style={{ fontSize: '16px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Bell size={18} color="#f85149" /> Cảnh báo bảo mật
                    </h2>
                    <p
                        style={{
                            color: '#8b949e',
                            fontSize: '12px',
                            marginTop: '4px',
                        }}
                    >
                        Các sự kiện đáng ngờ được phát hiện trong phiên capture
                    </p>
                </div>

                {/* Nút refresh */}
                <button className="btn btn--clear" onClick={fetchAlerts} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <RefreshCw size={14} /> Refresh
                </button>

                {/* Danh sách alert */}
                {alerts.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-state__icon">
                            <CheckCircle size={40} color="#3fb950" />
                        </div>
                        <div>Không có cảnh báo nào</div>
                        <div className="empty-state__text">
                            Hệ thống đang hoạt động bình thường
                        </div>
                    </div>
                ) : (
                    <div className="alert-list">
                        {alerts.map((alert) => (
                            <div key={alert.id} className="alert-card">
                                <span className="alert-card__time">
                                    {alert.time}
                                </span>
                                <span className="alert-card__type">
                                    {alert.type}
                                </span>
                                <span className="alert-card__message">
                                    {alert.message}
                                </span>
                            </div>
                        ))}
                    </div>
                )}

                {arpAlerts.length > 0 && (
                    <div style={{
                        background: 'rgba(248, 81, 73, 0.1)',
                        border: '2px solid #f85149',
                        borderRadius: '8px',
                        padding: '12px 16px',
                        marginBottom: '16px'
                    }}>
                        <div style={{ color: '#f85149', fontWeight: 700, marginBottom: '8px' }}>
                            🚨 Phát hiện ARP Spoofing!
                        </div>
                        {arpAlerts.map((alert, i) => (
                            <div key={i} style={{ color: '#e6edf3', fontSize: '13px', marginTop: '4px' }}>
                                ⚠️ [{alert.time}] {alert.message}
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}

export default Alerts;
