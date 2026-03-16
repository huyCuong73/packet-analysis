import { useState } from 'react';

function DetailSection({ title, children, defaultOpen = true }) {
    const [isOpen, setIsOpen] = useState(defaultOpen);

    return (
        <div className="detail-panel__section">
            {/* Header có thể click để đóng/mở */}
            <div
                className={`detail-panel__section-header ${isOpen ? 'detail-panel__section-header--open' : ''}`}
                onClick={() => setIsOpen(!isOpen)}
            >
                {title}
            </div>

            {/* Nội dung bên trong */}
            {isOpen && <div className="detail-panel__fields">{children}</div>}
        </div>
    );
}

export default DetailSection;
