import { io } from 'socket.io-client';

const socket = io('http://localhost:5000', {
    transports: ['websocket'],
    autoConnect: true,
});

socket.on('connect', () => {
    console.log('websocket connected');
});

socket.on('disconnect', () => {
    console.log('websocket disconnected');
});

export default socket;
