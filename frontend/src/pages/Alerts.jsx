import { useState, useEffect } from 'react';
import axios from 'axios';
import '../styles/_alerts.scss';

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
                    <h2 style={{ fontSize: '16px', fontWeight: 700 }}>
                        🚨 Cảnh báo bảo mật
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
                <button className="btn btn--clear" onClick={fetchAlerts}>
                    🔄 Refresh
                </button>

                {/* Danh sách alert */}
                {alerts.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-state__icon">✅</div>
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
            </div>
        </div>
    );
}

export default Alerts;
