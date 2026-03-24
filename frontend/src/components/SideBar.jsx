import { NavLink } from 'react-router-dom';
import { Shield, Activity, Bell, FileText, Search, Key } from 'lucide-react';

function Sidebar({ alertCount = 0 }) {
    return (
        <aside className="sidebar">
            <div className="sidebar__logo">
                <Shield size={24} color="#e6edf3" />
                <span className="sidebar__logo-text">Network Monitor</span>
            </div>
            <div className="sidebar__divider" />

            <NavLink
                to="/"
                end
                className={({ isActive }) =>
                    `nav-item ${isActive ? 'nav-item--active' : ''}`
                }
            >
                <div className="nav-item__icon"><Activity size={20} /></div>
                <span className="nav-item__label">Dashboard</span>
            </NavLink>

            <NavLink
                to="/alerts"
                className={({ isActive }) =>
                    `nav-item ${isActive ? 'nav-item--active' : ''}`
                }
            >
                <div className="nav-item__icon">
                    <Bell size={20} />
                    {alertCount > 0 && (
                        <span className="nav-item__badge">
                            {alertCount > 99 ? '99+' : alertCount}
                        </span>
                    )}
                </div>
                <span className="nav-item__label">Alerts</span>
            </NavLink>

            <NavLink
                to="/sessions"
                className={({ isActive }) =>
                    `nav-item ${isActive ? 'nav-item--active' : ''}`
                }
            >
                <div className="nav-item__icon"><FileText size={20} /></div>
                <span className="nav-item__label">Sessions</span>
            </NavLink>

            <NavLink
                to="/dns-timeline"
                className={({ isActive }) =>
                    `nav-item ${isActive ? 'nav-item--active' : ''}`
                }
            >
                <div className="nav-item__icon"><Search size={20} /></div>
                <span className="nav-item__label">DNS Timeline</span>
            </NavLink>

            <NavLink
                to="/credentials"
                className={({ isActive }) =>
                    `nav-item ${isActive ? 'nav-item--active' : ''}`
                }
            >
                <div className="nav-item__icon"><Key size={20} /></div>
                <span className="nav-item__label">Credential Leaks</span>
            </NavLink>
        </aside>
    );
}

export default Sidebar;
