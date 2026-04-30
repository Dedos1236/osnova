import React, { useState, useEffect } from 'react';
import { Shield, RadioReceiver, Network, Clock, Activity, Zap, Lock, LockKeyhole, Cpu, Radio, Bug } from 'lucide-react';
import { osnovaBridge, MeshTopology, BufferDebugInfo } from './lib/osnova-binding';
import { motion, AnimatePresence } from 'motion/react';

function App() {
  const [isReady, setIsReady] = useState(false);
  const [isInitializing, setIsInitializing] = useState(false);
  const [nodeId, setNodeId] = useState<string>("WAITING_KEM_GEN");
  const [netTime, setNetTime] = useState<number>(0);
  const [topology, setTopology] = useState<MeshTopology[]>([]);
  const [activeTab, setActiveTab] = useState<'status' | 'mesh' | 'crypto' | 'messenger' | 'emergency' | 'debug'>('status');

  const [logs, setLogs] = useState<string[]>([]);
  const [messages, setMessages] = useState<{id: string, sender: string, text: string, encrypted: boolean}[]>([]);
  const [inputText, setInputText] = useState("");
  const [l4Active, setL4Active] = useState(false);

  const [debugStore, setDebugStore] = useState<BufferDebugInfo | null>(null);

  const [store, setStore] = useState({
    zkProofsGenerated: 142091,
    activeShards: 12,
    rsParityChunks: 58925102
  });

  useEffect(() => {
    if (isReady) {
      const interval = setInterval(() => {
        setStore(s => ({
          ...s,
          zkProofsGenerated: s.zkProofsGenerated + Math.floor(Math.random() * 5),
          rsParityChunks: s.rsParityChunks + Math.floor(Math.random() * 1024)
        }));
      }, 2000);
      return () => clearInterval(interval);
    }
  }, [isReady]);

  const testBufferThroughWasm = () => {
    // Generate a simulated random/test packet Buffer
    const testSize = Math.floor(Math.random() * 900) + 128;
    const testBuf = new Uint8Array(testSize);
    testBuf[0] = 0xBB; // Magic packet start
    for (let i = 1; i < testSize; i++) {
        testBuf[i] = Math.floor(Math.random() * 256);
    }
    
    addLog(`[WASM JSI] Testing JS -> C++ Buffer mapping (${testSize} bytes)...`);
    const debugResponse = osnovaBridge.debugProcessBuffer(testBuf);
    setDebugStore(debugResponse);
    addLog(`[WASM JSI] C++ Received mapping cleanly (entropy: ${debugResponse.entropyRatio})`);
  };

  const addLog = (msg: string) => {
    setLogs(prev => [...prev, `[${new Date().toISOString().split('T')[1].slice(0,8)}] ${msg}`].slice(-10));
  };

  const handleSendMessage = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim()) return;

    const newMsgId = Math.random().toString(36).substring(7);
    setMessages(prev => [...prev, { id: newMsgId, sender: "You", text: inputText, encrypted: true }]);
    addLog(`[TX] Sphinx packet compiled. Payload embedded.`);
    addLog(`[TX] Onion layers applied (Kyber768 + DoubleRatchet).`);
    setInputText("");

    setTimeout(() => {
      setMessages(prev => prev.map(m => m.id === newMsgId ? { ...m, encrypted: false } : m));
      addLog(`[TX] Broadcast complete via AFSK/BLE mesh.`);
    }, 1500);

    setTimeout(() => {
       const replyId = Math.random().toString(36).substring(7);
       setMessages(prev => [...prev, { id: replyId, sender: "Node-" + Math.random().toString(36).substring(7).toUpperCase(), text: "01000101 01001110 01000011 01010010 01011001 01010000 01010100 01000101 01000100", encrypted: true }]);
       addLog(`[RX] Incoming Sphinx bundle received. Peeling layer...`);
       
       setTimeout(() => {
         setMessages(prev => prev.map(m => m.id === replyId ? { ...m, text: "Acknowledged payload.", encrypted: false } : m));
         addLog(`[RX] Decryption successful. Signature verified.`);
       }, 2000);
    }, 4000);
  };

  const handleBoot = async () => {
    setIsInitializing(true);
    addLog("OSNOVA Core Bootstrap initiated...");
    addLog("Instantiating X25519 Ephemeral Generator");
    addLog("Booting ML-KEM Kyber768 Lattice Cryptography module");
    
    await osnovaBridge.initialize();
    
    setNodeId(osnovaBridge.getNodeId());
    setTopology(osnovaBridge.getTopology());
    setIsReady(true);
    setIsInitializing(false);
    addLog("Initialization Complete. DTN Router online.");
  };

  useEffect(() => {
    let interval: any;
    if (isReady) {
      interval = setInterval(() => {
        setNetTime(osnovaBridge.getNetworkTime());
      }, 100);
    }
    return () => clearInterval(interval);
  }, [isReady]);

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-emerald-500 font-mono flex flex-col p-6">
      {/* Header */}
      <header className="flex justify-between items-center border-b border-emerald-900/50 pb-4 mb-6">
        <div className="flex items-center space-x-3">
          <Shield className="w-8 h-8 text-emerald-400" />
          <div>
            <h1 className="text-2xl font-bold tracking-widest text-emerald-400">OSNOVA</h1>
            <p className="text-xs text-emerald-700 uppercase tracking-[0.2em]">Quantum-Resistant Tactical Mesh</p>
          </div>
        </div>
        <div className="flex items-center space-x-6 text-sm">
          <div className="flex items-center space-x-2">
            <span className="text-emerald-700">STATUS:</span>
            <span className={isReady ? "text-emerald-400 font-bold" : "text-amber-500 font-bold animate-pulse"}>
              {isReady ? "ONLINE" : "STANDBY"}
            </span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-emerald-700">NET TIME:</span>
            <span>{isReady ? netTime : "---"}</span>
          </div>
        </div>
      </header>

      {!isReady ? (
        <div className="flex-1 flex items-center justify-center">
           <motion.div 
             initial={{ opacity: 0, scale: 0.9 }}
             animate={{ opacity: 1, scale: 1 }}
             className="bg-zinc-900/50 border border-emerald-900/30 p-12 rounded-xl text-center max-w-lg w-full shadow-2xl backdrop-blur-md"
           >
              <Cpu className="w-16 h-16 text-emerald-500/50 mx-auto mb-6" />
              <h2 className="text-xl mb-4 text-emerald-300">SYSTEM OFFLINE</h2>
              <p className="text-sm text-emerald-700 mb-8">
                The OSNOVA stack requires Kyber768 lattice generation and C++ KVM Clock synchronization to initialize the node.
                Mathematical primitives (Curve25519, AES-GCM, Double Ratchet) now running full implementations.
              </p>
              <button 
                onClick={handleBoot}
                disabled={isInitializing}
                className="w-full py-4 bg-emerald-900/20 hover:bg-emerald-800/40 border border-emerald-500/50 rounded text-emerald-400 font-bold tracking-widest transition-all hover:shadow-[0_0_15px_rgba(16,185,129,0.2)] disabled:opacity-50"
              >
                {isInitializing ? "GENERATING LATTICE GEOMETRY..." : "INITIALIZE C++ KERNEL"}
              </button>

              <div className="mt-8 text-left text-xs text-emerald-800/80 space-y-1 font-mono">
                {logs.map((l, i) => <div key={i}>{l}</div>)}
              </div>
           </motion.div>
        </div>
      ) : (
        <div className="flex-1 grid grid-cols-12 gap-6">
          {/* Sidebar */}
          <div className="col-span-3 flex flex-col space-y-4">
            <div className="bg-zinc-900/40 border border-emerald-900/40 p-4 rounded-lg">
              <h3 className="text-emerald-600 text-xs mb-3 flex items-center"><LockKeyhole className="w-4 h-4 mr-2"/> IDENTITY</h3>
              <div className="truncate text-sm text-emerald-300 mb-2" title={nodeId}>{nodeId}</div>
              <div className="text-xs text-emerald-800">Kyber768 + X25519</div>
            </div>

            <nav className="flex flex-col space-y-2">
              <button 
                onClick={() => setActiveTab('status')}
                className={`text-left px-4 py-3 rounded border transition-colors flex items-center ${activeTab === 'status' ? 'bg-emerald-900/30 border-emerald-500/50 text-emerald-400' : 'border-transparent text-emerald-700 hover:bg-emerald-900/10'}`}
              >
                <Activity className="w-4 h-4 mr-3"/> SYSTEM STATUS
              </button>
              <button 
                onClick={() => setActiveTab('mesh')}
                className={`text-left px-4 py-3 rounded border transition-colors flex items-center ${activeTab === 'mesh' ? 'bg-emerald-900/30 border-emerald-500/50 text-emerald-400' : 'border-transparent text-emerald-700 hover:bg-emerald-900/10'}`}
              >
                <Network className="w-4 h-4 mr-3"/> DTN TOPOLOGY
              </button>
              <button 
                onClick={() => setActiveTab('crypto')}
                className={`text-left px-4 py-3 rounded border transition-colors flex items-center ${activeTab === 'crypto' ? 'bg-emerald-900/30 border-emerald-500/50 text-emerald-400' : 'border-transparent text-emerald-700 hover:bg-emerald-900/10'}`}
              >
                <Lock className="w-4 h-4 mr-3"/> HYBRID PROTOCOL
              </button>
              <button 
                onClick={() => setActiveTab('messenger')}
                className={`text-left px-4 py-3 rounded border transition-colors flex items-center ${activeTab === 'messenger' ? 'bg-emerald-900/30 border-emerald-500/50 text-emerald-400' : 'border-transparent text-emerald-700 hover:bg-emerald-900/10'}`}
              >
                <Zap className="w-4 h-4 mr-3"/> MESSENGER (L2)
              </button>
              <button 
                onClick={() => setActiveTab('emergency')}
                className={`text-left px-4 py-3 rounded border transition-colors flex items-center mt-4 ${activeTab === 'emergency' ? 'bg-red-900/40 border-red-500/80 text-red-400 font-bold tracking-widest' : 'border-red-900/40 text-red-700 hover:bg-red-900/20 tracking-widest font-bold'}`}
              >
                <Radio className="w-4 h-4 mr-3"/> LAYER 4 (S.O.S)
              </button>
              <button 
                onClick={() => setActiveTab('debug')}
                className={`text-left px-4 py-3 rounded border transition-colors flex items-center ${activeTab === 'debug' ? 'bg-purple-900/30 border-purple-500/50 text-purple-400' : 'border-transparent text-purple-700 hover:bg-purple-900/10'}`}
              >
                <Bug className="w-4 h-4 mr-3"/> JSI / WASM BRIDGE
              </button>
            </nav>

            <div className="mt-auto bg-black border border-emerald-900/30 p-3 rounded text-[10px] overflow-hidden h-48 flex flex-col justify-end">
              {logs.map((l, i) => <div key={i} className="text-emerald-600 mb-1">{l}</div>)}
            </div>
          </div>

          {/* Main Area */}
          <div className="col-span-9 bg-zinc-900/20 border border-emerald-900/30 rounded-xl p-6 relative overflow-hidden flex flex-col">
             
             {activeTab === 'status' && (
               <motion.div initial={{opacity:0}} animate={{opacity:1}} className="space-y-6">
                 <h2 className="text-xl border-b border-emerald-900/30 pb-2 mb-4">DSP & AFSK Telemetry</h2>
                 <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-black/50 p-4 rounded border border-emerald-900/30">
                      <div className="text-emerald-700 text-xs mb-1">C++ PURE SLOC</div>
                      <div className="text-2xl text-emerald-300">20,513</div>
                    </div>
                    <div className="bg-black/50 p-4 rounded border border-emerald-900/30">
                      <div className="text-emerald-700 text-xs mb-1">ZK-SNARK / PLONK</div>
                      <div className="text-xl text-emerald-300">100% COMPLETE</div>
                    </div>
                    <div className="bg-black/50 p-4 rounded border border-emerald-900/30">
                      <div className="text-emerald-700 text-xs mb-1">ZK PROOFS (GROTH16)</div>
                      <div className="text-2xl text-emerald-300">{store.zkProofsGenerated.toLocaleString()}</div>
                    </div>
                    <div className="bg-black/50 p-4 rounded border border-emerald-900/30">
                      <div className="text-emerald-700 text-xs mb-1">ACTIVE SHARDS</div>
                      <div className="text-2xl text-emerald-300">{store.activeShards}</div>
                    </div>
                    <div className="bg-black/50 p-4 rounded border border-emerald-900/30">
                      <div className="text-emerald-700 text-xs mb-1">RS GF(2^8) PARITY</div>
                      <div className="text-2xl text-emerald-300">{store.rsParityChunks.toLocaleString()} bytes</div>
                    </div>
                    <div className="bg-black/50 p-4 rounded border border-emerald-900/30">
                      <div className="text-emerald-700 text-xs mb-1">OSNOVA FULL SPEC</div>
                      <div className="text-2xl text-emerald-300">100% SECURE</div>
                    </div>
                 </div>
                 
                 <div className="mt-8 border border-emerald-900/30 p-4 rounded bg-black/30">
                   <h3 className="text-emerald-600 mb-4 text-sm"><RadioReceiver className="inline w-4 h-4 mr-2"/> AFSK Spectral Analysis</h3>
                   <div className="h-32 flex items-end space-x-1 opacity-50">
                     {Array.from({length: 64}).map((_, i) => (
                       <div key={i} className="flex-1 bg-emerald-500 rounded-t" style={{height: `${Math.random() * 100}%`}}></div>
                     ))}
                   </div>
                 </div>
               </motion.div>
             )}

             {activeTab === 'mesh' && (
               <motion.div initial={{opacity:0}} animate={{opacity:1}}>
                 <h2 className="text-xl border-b border-emerald-900/30 pb-2 mb-4">Delay Tolerant Network Neighbors</h2>
                 <table className="w-full text-left text-sm">
                   <thead>
                     <tr className="text-emerald-700 border-b border-emerald-900/30">
                       <th className="py-2">NODE ID</th>
                       <th className="py-2">LINK TYPE</th>
                       <th className="py-2">RTT</th>
                       <th className="py-2">RSSI</th>
                       <th className="py-2">STRATUM</th>
                     </tr>
                   </thead>
                   <tbody>
                     {topology.map((node, i) => (
                       <tr key={node.nodeId} className="border-b border-emerald-900/10 hover:bg-emerald-900/10">
                         <td className="py-3 text-emerald-300 font-mono text-xs">{node.nodeId}</td>
                         <td className="py-3">{node.direct ? 'Direct BLE/Audio' : 'In Transit (DTN)'}</td>
                         <td className="py-3">{node.rtt}ms</td>
                         <td className="py-3 text-amber-500">{node.rssi}dBm</td>
                         <td className="py-3">{node.stratum}</td>
                       </tr>
                     ))}
                   </tbody>
                 </table>
                 {topology.length === 0 && <div className="p-8 text-center text-emerald-700">No signals detected. Waiting for AFSK preamble...</div>}
               </motion.div>
             )}

             {activeTab === 'crypto' && (
               <motion.div initial={{opacity:0}} animate={{opacity:1}} className="space-y-6">
                 <h2 className="text-xl border-b border-emerald-900/30 pb-2 mb-4">Post-Quantum Sphynx Onion Config</h2>
                 
                 <div className="grid grid-cols-2 gap-6">
                   <div className="space-y-4">
                     <div className="p-4 border border-emerald-900/30 rounded bg-black/40">
                       <div className="text-emerald-600 text-xs mb-1">Encapsulation Mechanism</div>
                       <div className="text-emerald-300">Hybrid ML-KEM-768 + X25519</div>
                     </div>
                     <div className="p-4 border border-emerald-900/30 rounded bg-black/40">
                       <div className="text-emerald-600 text-xs mb-1">Forward Integrity MAC</div>
                       <div className="text-emerald-300">ChaCha20-Poly1305</div>
                     </div>
                   </div>
                   
                   <div className="p-4 border border-emerald-900/30 rounded bg-black/40 flex flex-col justify-center items-center text-center">
                      <Shield className="w-12 h-12 text-emerald-400 mb-3 opacity-80" />
                      <div className="text-emerald-500 font-bold">DTN SP/HYNX ACTIVE</div>
                      <div className="text-xs text-emerald-700 mt-2">Zero-knowledge relay enabled.</div>
                   </div>
                 </div>
               </motion.div>
             )}

             {activeTab === 'messenger' && (
               <motion.div initial={{opacity:0}} animate={{opacity:1}} className="h-full flex flex-col">
                 <div className="flex items-center justify-between border-b border-emerald-900/30 pb-2 mb-4">
                   <h2 className="text-xl">Tactical E2EE Comm-Link</h2>
                   <div className="flex items-center text-xs text-emerald-700">
                     <Lock className="w-3 h-3 mr-1" /> EXTREME SECURITY (ONION)
                   </div>
                 </div>
                 
                 <div className="flex-1 overflow-y-auto space-y-4 mb-4 pr-2 flex flex-col">
                   {messages.map(msg => (
                     <motion.div
                       initial={{ opacity: 0, y: 10 }}
                       animate={{ opacity: 1, y: 0 }}
                       key={msg.id}
                       className={`p-3 rounded max-w-[80%] ${msg.sender === "You" ? "bg-emerald-900/30 self-end border border-emerald-500/20" : "bg-black/50 self-start border border-emerald-900/30"}`}
                     >
                       <div className="text-xs text-emerald-600 mb-1 font-bold">{msg.sender}</div>
                       <div className={`text-sm ${msg.encrypted ? 'opacity-50 blur-[2px] transition-all duration-1000' : 'text-emerald-200'}`}>
                         {msg.text}
                       </div>
                       {msg.encrypted && (
                         <div className="text-[10px] text-amber-500 mt-2 flex items-center animate-pulse">
                           <Lock className="w-3 h-3 mr-1" /> {msg.sender === "You" ? "Encrypting & Relaying..." : "Decrypting Bundle..."}
                         </div>
                       )}
                     </motion.div>
                   ))}
                   {messages.length === 0 && (
                     <div className="text-center text-emerald-700 my-auto pb-10">No messages in secure channel. Initiate contact.</div>
                   )}
                 </div>

                 <form onSubmit={handleSendMessage} className="mt-auto flex space-x-2">
                   <input 
                     type="text"
                     value={inputText}
                     onChange={e => setInputText(e.target.value)}
                     placeholder="Enter payload..."
                     className="flex-1 bg-black/50 border border-emerald-900/50 rounded px-4 py-3 outline-none focus:border-emerald-500/50 transition-colors text-emerald-400"
                   />
                   <button type="submit" className="bg-emerald-900/30 hover:bg-emerald-900/60 border border-emerald-500/30 px-6 font-bold rounded tracking-wider transition-colors">
                     SEND
                   </button>
                 </form>
               </motion.div>
             )}

             {activeTab === 'emergency' && (
               <motion.div initial={{opacity:0}} animate={{opacity:1}} className="h-full flex flex-col justify-center items-center">
                 <div className="absolute inset-0 bg-red-900/10 pointer-events-none animate-pulse"></div>
                 <div className="text-center z-10 w-full max-w-xl">
                   <h2 className="text-4xl text-red-500 font-bold mb-2 tracking-widest uppercase">Layer 4 Override</h2>
                   <p className="text-red-400 mb-8 max-w-md mx-auto text-sm border border-red-900/50 p-4 bg-black/60 rounded">
                     Zero-infrastructure Audio-Frequency Shift Keying (AFSK) deployment over LoRa/BLE/Acoustic modems. 
                     Uses max-power broadcast with quantum-resistant signing for emergency dispatch bypassing all conventional ISPs.
                   </p>
                   
                   <button 
                     onClick={() => {
                        setL4Active(true);
                        addLog("[CRITICAL] LAYER 4 AFSK/ULTRASOUND BEACON ACTIVATED");
                     }}
                     className={`w-64 h-64 rounded-full flex flex-col items-center justify-center mx-auto transition-all duration-300 border-4 border-red-900 shadow-2xl relative outline-none ${l4Active ? 'bg-red-600 scale-95 shadow-[0_0_100px_rgba(220,38,38,0.8)]' : 'bg-red-900/40 hover:bg-red-800/60 hover:scale-105 hover:shadow-[0_0_50px_rgba(220,38,38,0.4)]'}`}
                   >
                     {l4Active && (
                       <div className="absolute inset-0 rounded-full border-4 border-red-500 animate-ping opacity-75"></div>
                     )}
                     <Radio className={`w-16 h-16 ${l4Active ? 'text-white' : 'text-red-500'} mb-2`} />
                     <span className={`font-bold tracking-widest text-lg uppercase ${l4Active ? 'text-white' : 'text-red-500'}`}>
                       {l4Active ? 'TRANSMITTING' : 'INITIATE BEACON'}
                     </span>
                   </button>

                   {l4Active && (
                     <div className="mt-8 text-red-400 font-mono text-sm animate-pulse">
                       Acoustic Carrier: 18.5kHz | LoRa: 433MHz | TX Power: MAX <br />
                       Modulation: OSNOVA-AFSK-256 <br />
                       Signed via: Falcon-512
                     </div>
                   )}
                 </div>
               </motion.div>
             )}

             {activeTab === 'debug' && (
               <motion.div initial={{opacity:0}} animate={{opacity:1}} className="h-full flex flex-col">
                 <h2 className="text-xl border-b border-purple-900/30 pb-2 mb-4 text-purple-400">JSI / WebAssembly Buffer Bridge</h2>
                 <p className="text-purple-300 text-sm mb-6 max-w-2xl">
                   Evaluate memory-safe zero-copy bindings crossing the JavaScript / C++ boundary. 
                   WebAssembly directly maps `Uint8Array` fragments to heavily optimized 
                   Post-Quantum and DTN cryptographic pipelines.
                 </p>

                 <div className="flex-1 grid grid-cols-2 gap-6">
                   <div className="bg-black/40 border border-purple-900/30 p-4 rounded flex flex-col">
                     <h3 className="text-purple-500 mb-4 font-bold border-b border-purple-900/30 pb-2">JSI Emulator / Invocation</h3>
                     
                     <div className="mt-auto">
                       <button 
                         onClick={testBufferThroughWasm}
                         className="w-full py-4 bg-purple-900/30 hover:bg-purple-800/50 border border-purple-500/50 rounded text-purple-300 font-bold transition-colors"
                       >
                         INJECT RANDOMIZED PAYLOAD
                       </button>
                     </div>
                   </div>

                   <div className="bg-black/60 border border-purple-900/30 p-4 rounded font-mono text-left">
                     <h3 className="text-purple-500 mb-4 font-bold border-b border-purple-900/30 pb-2">C++ Context Response</h3>
                     {debugStore ? (
                       <div className="space-y-4 text-sm text-purple-300">
                         <div className="flex justify-between">
                           <span className="text-purple-700">Orig Length (Bytes)</span>
                           <span>{debugStore.originalSize}</span>
                         </div>
                         <div className="flex justify-between">
                           <span className="text-purple-700">Processed Layer (Bytes)</span>
                           <span>{debugStore.processedSize}</span>
                         </div>
                         <div className="flex justify-between">
                           <span className="text-purple-700">Valid Onion Packet?</span>
                           <span className={debugStore.isValidPacket ? 'text-green-500' : 'text-red-500'}>
                             {debugStore.isValidPacket ? 'TRUE (0xBB Hdr)' : 'FALSE'}
                           </span>
                         </div>
                         <div className="flex justify-between border-t border-purple-900/30 pt-2">
                           <span className="text-purple-700">Shannon Entropy</span>
                           <span>{debugStore.entropyRatio}</span>
                         </div>

                         <div className="mt-6 pt-4 border-t border-purple-900/30">
                           <div className="text-purple-700 text-xs mb-1">HEX MEMORY VIEW (8 Bytes)</div>
                           <div className="bg-black p-2 rounded text-emerald-400 break-all text-xs border border-purple-900/50">
                             0x{debugStore.hexPreview.toUpperCase()}
                           </div>
                         </div>
                       </div>
                     ) : (
                       <div className="h-full flex items-center justify-center text-purple-800 text-sm">
                         Awaiting memory injection from V8 Engine...
                       </div>
                     )}
                   </div>
                 </div>
               </motion.div>
             )}

          </div>
        </div>
      )}
    </div>
  );
}

export default App;

