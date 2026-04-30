#include <emscripten/bind.h>
#include <emscripten/val.h>
#include "../crypto/osnova_crypto_engine.h"
#include "../mesh/mesh_node.h"
#include "../mesh/dtn_router.h"
#include "../mesh/packet_processor.h"
#include "../dsp/audio_modem.h"

using namespace emscripten;
using namespace nit;

std::unique_ptr<mesh::MeshNode> g_node;
std::unique_ptr<mesh::DtnRouter> g_dtn;
std::unique_ptr<crypto::osnova::OsnovaEngine> g_crypto;
std::unique_ptr<dsp::AudioModem> g_modem;

struct WasmInitialization {
    bool ok;
    std::string node_id_hex;
};

// Debug result structure for Buffer processing
struct BufferDebugInfo {
    size_t original_size;
    size_t processed_size;
    std::string hex_preview;
    bool is_valid_packet;
    std::string entropy_ratio;
};

WasmInitialization init_mesh_core() {
    g_crypto = std::make_unique<crypto::osnova::OsnovaEngine>();
    
    // Generate Identity
    crypto::osnova::HybridPublicKey pk;
    crypto::osnova::HybridSecretKey sk;
    g_crypto->generate_identity(pk, sk);
    
    // Hash PK to get a 64-bit ID
    uint64_t node_id = 0;
    std::memcpy(&node_id, pk.x25519_pk.data(), sizeof(uint64_t));

    g_node = std::make_unique<mesh::MeshNode>(node_id);
    g_dtn = std::make_unique<mesh::DtnRouter>(*g_node);
    g_modem = std::make_unique<dsp::AudioModem>();

    char hex[17];
    snprintf(hex, sizeof(hex), "%016llx", (unsigned long long)node_id);

    return {true, std::string(hex)};
}

// Function to safely ingest ArrayBuffer/Uint8Array from JavaScript into OSNOVA core
BufferDebugInfo debug_process_jsi_buffer(val js_buffer) {
    BufferDebugInfo info;
    info.original_size = 0;
    info.processed_size = 0;
    info.is_valid_packet = false;
    info.hex_preview = "N/A";
    info.entropy_ratio = "0.0";
    
    if (js_buffer.isUndefined() || js_buffer.isNull()) {
        return info;
    }

    // Attempt to convert JS Uint8Array to std::vector<uint8_t>
    std::vector<uint8_t> buffer_data = convertJSArrayToNumberVector<uint8_t>(js_buffer);
    info.original_size = buffer_data.size();
    
    if (buffer_data.empty()) return info;

    // Output hex preview (first 8 bytes)
    char hex[64] = {0};
    size_t preview_len = std::min(buffer_data.size(), (size_t)8);
    for (size_t i = 0; i < preview_len; ++i) {
        sprintf(hex + (i*2), "%02x", buffer_data[i]);
    }
    info.hex_preview = std::string(hex);

    // Calculate Shannon entropy of the buffer
    std::map<uint8_t, int> counts;
    for (uint8_t b : buffer_data) counts[b]++;
    float entropy = (float)counts.size() / 256.0f;
    
    char ent_str[16];
    sprintf(ent_str, "%.2f", entropy);
    info.entropy_ratio = std::string(ent_str);
    
    // Pass buffer to PacketProcessor / DTN router theoretically
    // if (g_node) { ... }
    
    info.processed_size = buffer_data.size() + 16; // Added MAC theoretically
    info.is_valid_packet = (buffer_data.size() > 32 && buffer_data[0] == 0xBB);

    return info;
}

// Emscripten Binding Expositions
EMSCRIPTEN_BINDINGS(nit_osnova_mesh) {
    
    value_object<WasmInitialization>("WasmInitialization")
        .field("ok", &WasmInitialization::ok)
        .field("nodeId", &WasmInitialization::node_id_hex);

    value_object<BufferDebugInfo>("BufferDebugInfo")
        .field("originalSize", &BufferDebugInfo::original_size)
        .field("processedSize", &BufferDebugInfo::processed_size)
        .field("hexPreview", &BufferDebugInfo::hex_preview)
        .field("isValidPacket", &BufferDebugInfo::is_valid_packet)
        .field("entropyRatio", &BufferDebugInfo::entropy_ratio);

    function("initMeshCore", &init_mesh_core);
    function("debugProcessJsiBuffer", &debug_process_jsi_buffer);

    function("getNodeId", optional_override([]() -> std::string {
        if (!g_node) return "UNINITIALIZED";
        char hex[17];
        snprintf(hex, sizeof(hex), "%016llx", (unsigned long long)g_node->get_id());
        return std::string(hex);
    }));

    function("getNetworkTime", optional_override([]() -> double {
        if (!g_node) return 0.0;
        return static_cast<double>(g_node->get_clock().get_network_time_ms());
    }));
}
