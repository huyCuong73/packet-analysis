import { useState } from 'react';
import { Search, X } from 'lucide-react';

function FilterBar({ totalCount, filteredCount, onFilterChange }) {
    const [search, setSearch] = useState('');
    const [protocol, setProtocol] = useState('');
    const [port, setPort] = useState('');

    const handleChange = (field, value) => {
        const newFilters = {
            search: field === 'search' ? value : search,
            protocol: field === 'protocol' ? value : protocol,
            port: field === 'port' ? value : port,
        };

        if (field === 'search') setSearch(value);
        if (field === 'protocol') setProtocol(value);
        if (field === 'port') setPort(value);

        onFilterChange(newFilters);
    };

    const handleReset = () => {
        setSearch('');
        setProtocol('');
        setPort('');
        onFilterChange({ search: '', protocol: '', port: '' });
    };

    const hasFilters = search || protocol || port;

    return (
        <div className="filter-bar">
            <span className="filter-bar__icon"><Search size={14} /></span>

            <input
                className="filter-bar__input filter-bar__input--search"
                type="text"
                placeholder="Lọc theo IP..."
                value={search}
                onChange={(e) => handleChange('search', e.target.value)}
            />

            <select
                className="filter-bar__select"
                value={protocol}
                onChange={(e) => handleChange('protocol', e.target.value)}
            >
                <option value="">Tất cả Protocol</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="DNS">DNS</option>
                <option value="HTTP">HTTP</option>
                <option value="ICMP">ICMP</option>
                <option value="ARP">ARP</option>
            </select>

            <input
                className="filter-bar__input filter-bar__input--port"
                type="text"
                placeholder="Port..."
                value={port}
                onChange={(e) => handleChange('port', e.target.value)}
            />

            {hasFilters && (
                <button className="filter-bar__reset" onClick={handleReset} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <X size={14} /> Reset
                </button>
            )}

            <span className="filter-bar__count">
                {hasFilters
                    ? `${filteredCount} / ${totalCount} gói`
                    : `${totalCount} gói`}
            </span>
        </div>
    );
}

export default FilterBar;
