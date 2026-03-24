function InterfaceSelector({ interfaces, value, onChange, disabled, loading }) {
    if (loading) {
        return (
            <span style={{ color: '#8b949e', fontSize: '12px' }}>
                ⏳ Loading...
            </span>
        );
    }

    return (
        <select
            className="iface-select"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            disabled={disabled}
            title="Select network interface"
        >
            <option value="auto">🔀 Auto</option>

            {interfaces.map((iface) => (
                <option key={iface.name} value={iface.name}>
                    {iface.description || iface.name}
                    {iface.ip && iface.ip !== '0.0.0.0' ? ` — ${iface.ip}` : ''}
                </option>
            ))}
        </select>
    );
}

function _shortName(name) {
    if (name.includes('NPF_')) {
        const parts = name.split('NPF_');
        return 'NPF_' + parts[1].substring(0, 8) + '...';
    }
    return name;
}

export default InterfaceSelector;
