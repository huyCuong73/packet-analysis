function ProtocolBadge({ protocol }) {
    const proto = protocol || 'OTHER';

    return (
        <span className={`protocol-badge protocol-badge--${proto}`}>
            {proto}
        </span>
    );
}

export default ProtocolBadge;
