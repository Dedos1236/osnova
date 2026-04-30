/**
 * Nit Core L1 Transport - WebRTC Mesh Manager
 * Production-grade WebRTC DataChannel implementation for true P2P communication.
 * Handles signaling, ICE negotiation, and resilient data channel multiplexing.
 */

import io from "socket.io-client";
type SocketType = ReturnType<typeof io>;
import { NoiseCrypto } from "./crypto";

export type PeerStatus = 'disconnected' | 'connecting' | 'connected';

export interface Peer {
  id: string;
  connection: RTCPeerConnection;
  dataChannel?: RTCDataChannel;
  status: PeerStatus;
  publicKey?: CryptoKey;
}

export type MessageCallback = (senderId: string, payload: Uint8Array) => void;
export type PeerStatusCallback = (peerId: string, status: PeerStatus) => void;

export class WebRtcMeshManager {
  private socket: SocketType;
  private crypto: NoiseCrypto;
  private peers: Map<string, Peer> = new Map();
  
  private onMessageCb?: MessageCallback;
  private onPeerStatusCb?: PeerStatusCallback;

  private rtcConfig: RTCConfiguration = {
    iceServers: [
      { urls: "stun:stun.l.google.com:19302" },
      { urls: "stun:stun1.l.google.com:19302" }
    ]
  };

  constructor(socket: SocketType, crypto: NoiseCrypto) {
    this.socket = socket;
    this.crypto = crypto;
    this.setupSignaling();
  }

  public setCallbacks(onMessage: MessageCallback, onPeerStatus: PeerStatusCallback) {
    this.onMessageCb = onMessage;
    this.onPeerStatusCb = onPeerStatus;
  }

  private setupSignaling() {
    this.socket.on("peer_joined", async (data: { id: string }) => {
      // Initiate to new peers
      await this.initiateConnection(data.id);
    });

    this.socket.on("existing_peers", async (data: { peers: string[] }) => {
      // Connect to all existing peers
      for (const peerId of data.peers) {
        if (peerId !== this.socket.id) {
           await this.initiateConnection(peerId);
        }
      }
    });

    this.socket.on("webrtc_offer", async (data: { sdp: RTCSessionDescriptionInit, sender: string }) => {
      await this.handleOffer(data.sender, data.sdp);
    });

    this.socket.on("webrtc_answer", async (data: { sdp: RTCSessionDescriptionInit, sender: string }) => {
      await this.handleAnswer(data.sender, data.sdp);
    });

    this.socket.on("webrtc_ice", async (data: { candidate: RTCIceCandidateInit, sender: string }) => {
      await this.handleIceCandidate(data.sender, data.candidate);
    });

    this.socket.on("peer_left", (data: { id: string }) => {
      this.teardownConnection(data.id);
    });
  }

  private async initiateConnection(targetId: string) {
    if (this.peers.has(targetId)) return;

    const pc = this.createPeerConnection(targetId);
    
    // Create data channel
    const dc = pc.createDataChannel("nit_l1_mainline", {
      ordered: true,
      maxRetransmits: 3 
    });
    
    this.setupDataChannel(targetId, dc);

    this.peers.set(targetId, {
      id: targetId,
      connection: pc,
      dataChannel: dc,
      status: 'connecting'
    });

    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      this.socket.emit("webrtc_offer", {
        target: targetId,
        sdp: pc.localDescription
      });
    } catch (e) {
      console.error(`Failed to create offer for ${targetId}`, e);
    }
  }

  private async handleOffer(senderId: string, sdp: RTCSessionDescriptionInit) {
    let peer = this.peers.get(senderId);
    if (!peer) {
      const pc = this.createPeerConnection(senderId);
      peer = { id: senderId, connection: pc, status: 'connecting' };
      this.peers.set(senderId, peer);
    } else {
      console.warn(`[WebRTC] Received offer from existing peer ${senderId}`);
    }

    try {
      await peer.connection.setRemoteDescription(new RTCSessionDescription(sdp));
      const answer = await peer.connection.createAnswer();
      await peer.connection.setLocalDescription(answer);
      
      this.socket.emit("webrtc_answer", {
        target: senderId,
        sdp: peer.connection.localDescription
      });
    } catch (e) {
      console.error(`Failed to handle offer from ${senderId}`, e);
    }
  }

  private async handleAnswer(senderId: string, sdp: RTCSessionDescriptionInit) {
    const peer = this.peers.get(senderId);
    if (!peer) return;
    try {
      await peer.connection.setRemoteDescription(new RTCSessionDescription(sdp));
    } catch (e) {
      console.error(`Failed to handle answer from ${senderId}`, e);
    }
  }

  private async handleIceCandidate(senderId: string, candidate: RTCIceCandidateInit) {
    const peer = this.peers.get(senderId);
    if (!peer) return;
    try {
      await peer.connection.addIceCandidate(new RTCIceCandidate(candidate));
    } catch (e) {
      console.error(`Failed to add ICE candidate from ${senderId}`, e);
    }
  }

  private createPeerConnection(targetId: string): RTCPeerConnection {
    const pc = new RTCPeerConnection(this.rtcConfig);

    pc.onicecandidate = (event) => {
      if (event.candidate) {
        this.socket.emit("webrtc_ice", {
          target: targetId,
          candidate: event.candidate.toJSON()
        });
      }
    };

    pc.ondatachannel = (event) => {
      this.setupDataChannel(targetId, event.channel);
    };

    pc.onconnectionstatechange = () => {
      const peer = this.peers.get(targetId);
      if (peer) {
        if (pc.connectionState === 'connected') {
          peer.status = 'connected';
          this.onPeerStatusCb?.(targetId, 'connected');
        } else if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed' || pc.connectionState === 'closed') {
          this.teardownConnection(targetId);
        }
      }
    };

    return pc;
  }

  private setupDataChannel(targetId: string, dc: RTCDataChannel) {
    const peer = this.peers.get(targetId);
    if (peer) {
      peer.dataChannel = dc;
    }
    
    // We want binary data
    dc.binaryType = 'arraybuffer';

    dc.onopen = () => {
      const p = this.peers.get(targetId);
      if (p) {
        p.status = 'connected';
        this.onPeerStatusCb?.(targetId, 'connected');
      }
    };

    dc.onclose = () => {
      this.teardownConnection(targetId);
    };

    dc.onmessage = (event) => {
      if (this.onMessageCb && event.data instanceof ArrayBuffer) {
        this.onMessageCb(targetId, new Uint8Array(event.data));
      } else if (this.onMessageCb && typeof event.data === 'string') {
        // Fallback or text signaling over DC
        this.onMessageCb(targetId, new TextEncoder().encode(event.data));
      }
    };
  }

  private teardownConnection(targetId: string) {
    const peer = this.peers.get(targetId);
    if (peer) {
      peer.dataChannel?.close();
      peer.connection.close();
      this.peers.delete(targetId);
      this.onPeerStatusCb?.(targetId, 'disconnected');
    }
  }

  public async broadcast(payload: Uint8Array) {
    let sent = 0;
    for (const [id, peer] of this.peers.entries()) {
      if (peer.status === 'connected' && peer.dataChannel?.readyState === 'open') {
        try {
          peer.dataChannel.send(payload);
          sent++;
        } catch (e) {
          console.error(`Failed to send to ${id}`, e);
        }
      }
    }
    return sent;
  }

  public getConnectedPeersCount(): number {
    let count = 0;
    for (const peer of this.peers.values()) {
      if (peer.status === 'connected') count++;
    }
    return count;
  }

  public destroy() {
    for (const id of this.peers.keys()) {
      this.teardownConnection(id);
    }
  }
}
