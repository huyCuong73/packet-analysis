import { useState, useEffect } from 'react';
import axios from 'axios';

export function useInterfaces() {
    const [interfaces, setInterfaces] = useState([]);
    const [selectedInterface, setSelectedInterface] = useState('');
    const [loading, setLoading] = useState(false);

    const fetchInterfaces = async () => {
        setLoading(true);
        try {
            const res = await axios.get(
                'http://localhost:5000/api/friendly-interfaces'
            );
            setInterfaces(res.data);

            setSelectedInterface('auto');
        } catch (err) {
            console.error('Lỗi lấy interfaces:', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchInterfaces();
    }, []);

    return {
        interfaces,
        selectedInterface,
        setSelectedInterface,
        loading,
        fetchInterfaces,
    };
}
