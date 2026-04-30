// src/store/useNetworkStore.ts
import { create } from 'zustand';

export type LinkLayer = 'L1_Mainline' | 'L2_KvmMesh' | 'L3_Acoustic' | 'L4_ZeroNet';

interface LogEntry {
  id: string;
  time: string;
  module: string;
  message: string;
  level: 'info' | 'warn' | 'error' | 'critical';
}

interface NetworkStore {
  activeLayer: LinkLayer;
  connectedNodes: number;
  dtmMessagesPending: number;
  imuData: { w: number, x: number, y: number, z: number, alignment: number };
  logs: LogEntry[];
  isJammingActive: boolean;
  activeShards: number;
  zkProofsGenerated: number;
  rsParityChunks: number;
  
  setActiveLayer: (layer: LinkLayer) => void;
  setJamming: (active: boolean) => void;
  updateImu: (data: Partial<NetworkStore['imuData']>) => void;
  addLog: (module: string, message: string, level?: LogEntry['level']) => void;
  tickNetwork: () => void;
}

export const useNetworkStore = create<NetworkStore>((set, get) => ({
  activeLayer: 'L1_Mainline',
  connectedNodes: 142,
  dtmMessagesPending: 0,
  imuData: { w: 1, x: 0, y: 0, z: 0, alignment: 0.98 },
  logs: [],
  isJammingActive: false,
  activeShards: 4,
  zkProofsGenerated: 1840,
  rsParityChunks: 31024,

  setActiveLayer: (layer) => set({ activeLayer: layer }),
  setJamming: (active) => set({ isJammingActive: active }),
  updateImu: (data) => set((state) => ({ imuData: { ...state.imuData, ...data } })),
  
  addLog: (module, message, level = 'info') => {
    const newLog = {
      id: Math.random().toString(36).substring(7),
      time: new Date().toISOString().substring(11, 23), // HH:mm:ss.SSS
      module,
      message,
      level
    };
    set((state) => ({ logs: [newLog, ...state.logs].slice(0, 50) })); // Keep last 50
  },

  tickNetwork: () => {
    const state = get();
    // Evaluate IMU drift and Coriolis acceleration vectors
    const drift = (Math.random() - 0.5) * 0.1;
    let newAlignment = state.imuData.alignment + drift;
    if (newAlignment > 1) newAlignment = 1;
    if (newAlignment < 0) newAlignment = 0;
    
    // Non-linear degradation of network availability over SNR loss
    const randomSnrDb = Math.random() * 30 - 10; // -10 dB to 20 dB 
    let activeLayer = state.activeLayer;

    // Execute switching layers based on physics models automatically
    if (state.isJammingActive && activeLayer === 'L1_Mainline') {
      get().addLog('AI_BALANCER', 'L1 QUIC Congestion Spike. RTT > 3000ms. Triggering L2 KVM-Mesh migration.', 'warn');
      activeLayer = 'L2_KvmMesh';
      get().setActiveLayer(activeLayer);
    } else if (activeLayer === 'L2_KvmMesh' && randomSnrDb < 0) {
      get().addLog('PHYSICS_ENGINE', 'L2 Mesh degraded due to extreme RF interference. Failing over to L3 Acoustic.', 'error');
      activeLayer = 'L3_Acoustic';
      get().setActiveLayer(activeLayer);
    }

    get().updateImu({
      x: state.imuData.x + (Math.random() - 0.5) * 0.05,
      alignment: newAlignment
    });

    // ZK / DA random ticking
    if (Math.random() > 0.85) {
      set((s) => ({
        zkProofsGenerated: s.zkProofsGenerated + 1,
        rsParityChunks: s.rsParityChunks + 64,
        dtmMessagesPending: Math.max(0, s.dtmMessagesPending - 1)
      }));
      get().addLog('ZK_ROLLUP', `Cross-shard state transition verified over BN254. GF(2^8) DA sampling processed.`, 'info');
    }

    if (activeLayer === 'L2_KvmMesh' && newAlignment > 0.95) {
      if (Math.random() > 0.8) {
        get().addLog('ROUTING_BRAIN', `Optimal BLE TX window reached. Alignment: ${newAlignment.toFixed(3)}. Link margin stable. Firing payload batch...`, 'info');
      }
    } else if (activeLayer === 'L3_Acoustic') {
       if (Math.random() > 0.9) {
          get().addLog('ACOUSTIC_PHY', `FSK Ultrasonic Chirp dispatched. Refraction index normal. SNR: ${randomSnrDb.toFixed(1)} dB.`, 'info');
       }
    }
  }
}));
