import { NavLink } from 'react-router-dom';

function Sidebar({ alertCount = 0 }) {
    return (
        <aside className="sidebar">
            <div className="sidebar__logo">🛡️</div>
            <div className="sidebar__divider" />

            <NavLink
                to="/"
                end
                className={({ isActive }) =>
                    `nav-item ${isActive ? 'nav-item--active' : ''}`
                }
            >
                📡
                <span className="nav-item__tooltip">Dashboard</span>
            </NavLink>

            <NavLink
                to="/alerts"
                className={({ isActive }) =>
                    `nav-item ${isActive ? 'nav-item--active' : ''}`
                }
            >
                🚨
                {alertCount > 0 && (
                    <span className="nav-item__badge">
                        {alertCount > 99 ? '99+' : alertCount}
                    </span>
                )}
                <span className="nav-item__tooltip">Alerts</span>
            </NavLink>

            {/* ← Thêm mới */}
            <NavLink
                to="/sessions"
                className={({ isActive }) =>
                    `nav-item ${isActive ? 'nav-item--active' : ''}`
                }
            >
                📋
                <span className="nav-item__tooltip">Sessions</span>
            </NavLink>
        </aside>
    );
}

export default Sidebar;
