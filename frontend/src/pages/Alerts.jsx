import { useState, useEffect } from 'react';
import axios from 'axios';
import '../styles/_alerts.scss';
import { Bell, RefreshCw, CheckCircle } from 'lucide-react';

function Alerts() {
    const [alerts, setAlerts] = useState([]);

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
        const interval = setInterval(fetchAlerts, 5000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="page-content">
            <div className="alerts-page">
                <div style={{ marginBottom: '16px' }}>
                    <h2 style={{ fontSize: '16px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Bell size={18} color="#f85149" /> Security Alerts
                    </h2>
                    <p
                        style={{
                            color: '#8b949e',
                            fontSize: '12px',
                            marginTop: '4px',
                        }}
                    >
                        Suspicious events detected in the capture session
                    </p>
                </div>

                <button className="btn btn--clear" onClick={fetchAlerts} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <RefreshCw size={14} /> Refresh
                </button>

                {alerts.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-state__icon">
                            <CheckCircle size={40} color="#3fb950" />
                        </div>
                        <div>No alerts found</div>
                        <div className="empty-state__text">
                            System is operating normally
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
