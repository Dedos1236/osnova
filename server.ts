import express from "express";
import { createServer as createViteServer } from "vite";
import http from "http";
import { Server } from "socket.io";
import path from "path";

async function startServer() {
  const app = express();
  const PORT = 3000;

  const server = http.createServer(app);
  
  // Real-time C2S messaging and WebRTC Signaling
  const io = new Server(server, {
    cors: { origin: "*" }
  });

  io.on("connection", (socket) => {
    console.log(`[C2S MAINLINE] L1 WebSocket Connected: ${socket.id}`);
    
    // Broadcast when a new peer joins
    socket.broadcast.emit("peer_joined", { id: socket.id });
    
    // Send existing peers to the new client
    io.fetchSockets().then((sockets) => {
       const peerIds = sockets.map(s => s.id).filter(id => id !== socket.id);
       socket.emit("existing_peers", { peers: peerIds });
    });

    socket.on("webrtc_offer", (data) => {
      // Forward SDP offer
      socket.to(data.target).emit("webrtc_offer", {
        sdp: data.sdp,
        sender: socket.id
      });
    });

    socket.on("webrtc_answer", (data) => {
      // Forward SDP answer
      socket.to(data.target).emit("webrtc_answer", {
        sdp: data.sdp,
        sender: socket.id
      });
    });

    socket.on("webrtc_ice", (data) => {
      // Forward ICE candidates
      socket.to(data.target).emit("webrtc_ice", {
        candidate: data.candidate,
        sender: socket.id
      });
    });

    // Keys exchange for End-to-End simulation (though in C2S keys are kept for SORM)
    socket.on("public_key_broadcast", (data) => {
      socket.broadcast.emit("peer_public_key", {
        sender: socket.id,
        publicKey: data.publicKey
      });
    });

    socket.on("chat_message", (data) => {
      // Centralized C2S messaging fallback if WebRTC datachannel isn't used
      socket.broadcast.emit("chat_message", data);
    });

    socket.on("disconnect", () => {
      console.log(`[C2S MAINLINE] Disconnected: ${socket.id}`);
      socket.broadcast.emit("peer_left", { id: socket.id });
    });
  });

  // API routes
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", layer: "L1_Mainline", encryption: "Noise_IK_Simulated" });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
