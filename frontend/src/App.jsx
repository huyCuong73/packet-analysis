import {
    BrowserRouter,
    Routes,
    Route,
    useSearchParams,
} from 'react-router-dom';
import { useSocket } from './hooks/useSocket';
import Navbar from './components/Navbar';
import Sidebar from './components/SideBar';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Sessions from './pages/Sessions';
import DnsTimeline from './pages/DnsTimeline';
import CredentialsPage from './pages/CredentialsPage';
import './styles/_layout.scss';
import './styles/_sidebar.scss';

function App() {
    const socket = useSocket();

    return (
        <BrowserRouter>
            <div className="app">
                <Navbar isConnected={socket.isConnected} />
                <div className="layout">
                    <Sidebar />
                    <Routes>
                        <Route
                            path="/"
                            element={<Dashboard socket={socket} />}
                        />
                        <Route path="/alerts" element={<Alerts />} />
                        <Route path="/sessions" element={<Sessions />} />
                        <Route
                            path="/dns-timeline"
                            element={<DnsTimeline socket={socket} />}
                        />
                        <Route
                            path="/credentials"
                            element={<CredentialsPage socket={socket} />}
                        />
                    </Routes>
                </div>
            </div>
        </BrowserRouter>
    );
}

export default App;
