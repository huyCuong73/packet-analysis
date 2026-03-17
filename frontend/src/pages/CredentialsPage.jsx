import { useState, useMemo } from 'react'
import CredentialsTable from '../components/CredentialsTable'
import { Bell, Search, FileText } from 'lucide-react'

function CredentialsPage({ socket }) {
    const { packets, setSelectedId } = socket
    const [filterText, setFilterText] = useState('')

    const credentialsList = useMemo(() => {
        return packets
            .filter(pkt => pkt.credentials && pkt.credentials.length > 0)
            .map(pkt => ({
                id: pkt.id,
                time: pkt.time,
                src_ip: pkt.src_ip || '',
                dst_ip: pkt.dst_ip || '',
                credentials: pkt.credentials
            }))
            .reverse()
    }, [packets])

    const filteredList = useMemo(() => {
        if (!filterText) return credentialsList
        const q = filterText.toLowerCase()
        return credentialsList.filter(e => {
            if (e.src_ip.toLowerCase().includes(q) || e.dst_ip.toLowerCase().includes(q)) return true

            return e.credentials.some(c => c.value.toLowerCase().includes(q))
        })
    }, [credentialsList, filterText])

    const stats = useMemo(() => {
        const uniqueSrc = new Set(credentialsList.map(e => e.src_ip)).size
        const uniqueDst = new Set(credentialsList.map(e => e.dst_ip)).size
        return { uniqueSrc, uniqueDst, total: credentialsList.length }
    }, [credentialsList])

    return (
        <div className="page-content" style={{ padding: '16px' }}>
            <div style={{ marginBottom: '24px' }}>
                <h2 style={{
                    fontSize: '20px',
                    fontWeight: 700,
                    color: '#f85149',
                    margin: 0,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px'
                }}>
                    Báo cáo Rò rỉ Thông tin Đăng nhập
                </h2>
                <p style={{ color: '#8b949e', fontSize: '13px', marginTop: '6px' }}>
                    Danh sách các tài khoản (Username/Password) bị đánh cắp do hệ thống phát hiện chúng được truyền đi
                    trên mạng mà không có mã hóa (HTTP, FTP, Telnet).
                </p>
            </div>

            <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                background: '#0d1117',
                border: '1px solid #30363d',
                borderRadius: '8px',
                padding: '16px',
                marginBottom: '20px',
                flexWrap: 'wrap',
                gap: '16px'
            }}>
                <div style={{ display: 'flex', gap: '24px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <span style={{ color: '#8b949e', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Tổng số sự cố</span>
                        <span style={{ color: '#f85149', fontSize: '20px', fontWeight: 700 }}>{stats.total}</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <span style={{ color: '#8b949e', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Thiết bị bị hại (IP Nguồn)</span>
                        <span style={{ color: '#58a6ff', fontSize: '20px', fontWeight: 700 }}>{stats.uniqueSrc}</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <span style={{ color: '#8b949e', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Máy chủ lộ lọt (IP Đích)</span>
                        <span style={{ color: '#e3b341', fontSize: '20px', fontWeight: 700 }}>{stats.uniqueDst}</span>
                    </div>
                </div>

                <div style={{ position: 'relative' }}>
                    <div style={{ position: 'absolute', left: '12px', top: '10px', color: '#8b949e' }}>
                        <Search size={14} />
                    </div>
                    <input
                        type="text"
                        placeholder="Tìm kiếm IP, Username, Password..."
                        value={filterText}
                        onChange={(e) => setFilterText(e.target.value)}
                        style={{
                            background: '#161b22',
                            border: '1px solid #30363d',
                            borderRadius: '6px',
                            padding: '10px 14px 10px 34px',
                            color: '#e6edf3',
                            fontSize: '13px',
                            fontFamily: 'monospace',
                            width: '320px',
                            outline: 'none',
                        }}
                    />
                </div>
            </div>

            <div style={{
                background: '#0d1117',
                border: '1px solid #f85149',
                borderRadius: '8px',
                padding: '16px',
                minHeight: '400px'
            }}>
                <div style={{
                    fontSize: '13px',
                    fontWeight: 600,
                    color: '#f85149',
                    marginBottom: '16px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><FileText size={16} /> Chi tiết các vụ rò rỉ</span>
                    {filterText && (
                        <span style={{ color: '#8b949e', fontSize: '11px', fontWeight: 400 }}>
                            Đã lọc: <strong>{filteredList.length}</strong> / {credentialsList.length}
                        </span>
                    )}
                </div>

                <div style={{ maxHeight: 'calc(100vh - 350px)', overflowY: 'auto' }}>
                    <CredentialsTable
                        data={filteredList}
                        onSelectPacket={setSelectedId}
                    />
                </div>
            </div>
        </div>
    )
}

export default CredentialsPage
