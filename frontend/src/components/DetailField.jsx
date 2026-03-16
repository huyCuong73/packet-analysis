function DetailField({ label, value, highlight }) {
    // Tự động chọn màu dựa vào giá trị
    const getValueClass = () => {
        if (highlight === 'danger') return 'detail-panel__field-value--danger';
        if (highlight === 'ok') return 'detail-panel__field-value--ok';
        if (highlight === 'warn') return 'detail-panel__field-value--highlight';
        return '';
    };

    return (
        <div className="detail-panel__field">
            <span className="detail-panel__field-key">{label}</span>
            <span className={`detail-panel__field-value ${getValueClass()}`}>
                {value ?? '—'}
            </span>
        </div>
    );
}

export default DetailField;
