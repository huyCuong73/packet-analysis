import { Shield } from 'lucide-react';

function Navbar({ isConnected }) {
    return (
        <nav className="navbar">
            <div className="navbar__brand">
                <span className="navbar__brand-icon">
                    <Shield size={20} color="#58a6ff" style={{ verticalAlign: 'middle', marginBottom: '2px' }} />
                </span>
                py_nsm
                <span className="navbar__brand-sub">
                    Network Security Monitor
                </span>
            </div>

            <div className="navbar__status">
                <div
                    className={`navbar__status-dot ${isConnected ? 'navbar__status-dot--connected' : ''}`}
                />
                {isConnected ? 'Backend connected' : 'Backend disconnected'}
            </div>
        </nav>
    );
}

export default Navbar;
