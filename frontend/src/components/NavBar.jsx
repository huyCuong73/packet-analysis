function Navbar({ isConnected }) {
    return (
        <nav className="navbar">
            {/* Logo + tên */}
            <div className="navbar__brand">
                <span className="navbar__brand-icon">🛡️</span>
                py_nsm
                <span className="navbar__brand-sub">
                    Network Security Monitor
                </span>
            </div>

            {/* Trạng thái kết nối */}
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
