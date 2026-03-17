import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import '../styles/_sessions.scss';
import { FileText, RefreshCw, Inbox, Eye, Trash2 } from 'lucide-react';
import axios from 'axios';

function Sessions() {
    const [sessions, setSessions] = useState([]);
    const navigate = useNavigate();

    const fetchSessions = async () => {
        try {
            const res = await axios.get('http://localhost:5000/api/sessions');
            setSessions(res.data);
        } catch (err) {
            console.error(err);
        }
    };

    useEffect(() => {
        fetchSessions();
    }, []);

    const handleDelete = async (id) => {
        if (!window.confirm('Xóa phiên này?')) return;
        await axios.delete(`http://localhost:5000/api/sessions/${id}`);
        fetchSessions();
    };

    const handleView = (id) => {
        navigate(`/?session_id=${id}`);
    };

    return (
        <div className="page-content">
            <div className="sessions-page">
                <div style={{ marginBottom: '16px' }}>
                    <h2 style={{ fontSize: '16px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <FileText size={18} /> Lịch sử phiên capture
                    </h2>
                    <p
                        style={{
                            color: '#8b949e',
                            fontSize: '12px',
                            marginTop: '4px',
                        }}
                    >
                        Xem lại dữ liệu của các phiên bắt gói tin trước đó
                    </p>
                </div>

                <button className="btn btn--clear" onClick={fetchSessions} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <RefreshCw size={14} /> Refresh
                </button>

                {sessions.length === 0 ? (
                    <div
                        style={{
                            textAlign: 'center',
                            padding: '60px',
                            color: '#8b949e',
                        }}
                    >
                        <div style={{ fontSize: '40px' }}><Inbox size={48} strokeWidth={1} /></div>
                        <div style={{ marginTop: '12px' }}>
                            Chưa có phiên nào
                        </div>
                        <div style={{ fontSize: '12px', marginTop: '4px' }}>
                            Nhấn "Bắt đầu" ở Dashboard để tạo phiên đầu tiên
                        </div>
                    </div>
                ) : (
                    <div className="session-list">
                        {sessions.map((s) => (
                            <div key={s.id} className="session-card">
                                <div>
                                    <div className="session-card__name">
                                        {s.name}
                                    </div>
                                    <div className="session-card__time">
                                        {s.created_at}
                                    </div>
                                </div>

                                <span className="session-card__count">
                                    {s.packet_count} gói tin
                                </span>

                                <div className="session-card__actions">
                                    <button
                                        className="btn btn--start"
                                        onClick={() => handleView(s.id)}
                                        style={{ display: 'flex', alignItems: 'center', gap: '4px', padding: '4px 12px', fontSize: '12px' }}
                                    >
                                        <Eye size={12} /> Xem
                                    </button>
                                    <button
                                        className="btn btn--stop"
                                        onClick={() => handleDelete(s.id)}
                                        style={{ display: 'flex', alignItems: 'center', gap: '4px', padding: '4px 12px', fontSize: '12px' }}
                                    >
                                        <Trash2 size={12} /> Xóa
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}

export default Sessions;
