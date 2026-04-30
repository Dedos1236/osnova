cmake_minimum_required(VERSION 3.25)
project(NitMessenger VERSION 0.1.0 LANGUAGES CXX C)

# ==============================================================================
# Global Config
# ==============================================================================
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Strict warnings for hard-core engineering
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror -Wno-unused-parameter)
endif()

# ==============================================================================
# Platform specific configurations
# ==============================================================================
if(ANDROID OR IOS)
    add_compile_definitions(MOBILE_BUILD)
endif()

# ==============================================================================
# Dependencies (Using FetchContent or find_package in a real scenario)
# ==============================================================================
# find_package(Threads REQUIRED)
# find_package(asio REQUIRED)
# find_package(SQLite3 REQUIRED)
# ... qt6, ngtcp2, etc.

# ==============================================================================
# Core Library - The Unified C++ Brain
# ==============================================================================
add_library(nit_core STATIC
    src/core/routing/routing_brain.cpp
    src/core/quic/quic_engine.cpp
    src/core/quic/quic_connection.cpp
    src/core/crypto/noise_session.cpp
    src/core/crypto/osnova_crypto_engine.cpp
    src/core/crypto/onion_routing.cpp
    src/core/crypto/secure_enclave.cpp
    src/core/crypto/chacha20.cpp
    src/core/crypto/poly1305.cpp
    src/core/mesh/serialize.cpp
    src/core/mesh/routing_table.cpp
    src/core/mesh/session_manager.cpp
    src/core/mesh/rpc_schema.cpp
    src/core/mesh/rpc_dispatcher.cpp
    src/core/mesh/gossip_sub.cpp
    src/core/mesh/bbr_congestion.cpp
    src/core/mesh/sphinx_packet.cpp
    src/core/mesh/pbft_consensus.cpp
    src/core/mesh/merkle_trie.cpp
    src/core/mesh/blockchain_vm.cpp
    src/core/media/rtp_packetizer.cpp
    src/core/media/sdp_parser.cpp
    src/core/media/webrtc_ice.cpp
    src/core/media/h264_parser.cpp
    src/core/media/av1_parser.cpp
    src/core/media/opus_packetizer.cpp
    src/core/media/jitter_buffer.cpp
    src/core/media/srtp_session.cpp
    src/core/mesh/bencode.cpp
    src/core/mesh/torrent_engine.cpp
    src/core/mesh/kademlia_dht.cpp
    src/core/json/json_parser.cpp
    src/core/json/bson_parser.cpp
    src/core/db/lsm_tree.cpp
    src/core/crypto/aead_chacha20.cpp
    src/core/crypto/mtp_obfuscator.cpp
    src/core/crypto/spongent.cpp
    src/core/crypto/treekem.cpp
    src/core/crypto/bls.cpp
    src/core/crypto/falcon.cpp
    src/core/crypto/ntru.cpp
    src/core/crypto/sphincs_plus.cpp
    src/core/crypto/bulletproofs.cpp
    src/core/crypto/sm3.cpp
    src/core/crypto/sm4.cpp
    src/core/crypto/pq_kyber.cpp
    src/core/crypto/pq_dilithium.cpp
    src/core/crypto/gost_streebog.cpp
    src/core/crypto/gost_kuznyechik.cpp
    src/core/crypto/paillier.cpp
    src/core/crypto/zk_snark.cpp
    src/core/crypto/garbled_circuit.cpp
    src/core/crypto/ring_signature.cpp
    src/core/crypto/oprf.cpp
    src/core/crypto/vdf.cpp
    src/core/crypto/ecies.cpp
    src/core/crypto/double_ratchet.cpp
    src/core/crypto/osnova_handshake.cpp
    src/core/crypto/srp6a.cpp
    src/core/crypto/psi.cpp
    src/core/crypto/oblivious_transfer.cpp
    src/core/crypto/curve25519.cpp
    src/core/crypto/sha512.cpp
    src/core/crypto/hkdf.cpp
    src/core/crypto/kyber768.cpp
    src/core/crypto/ed25519.cpp
    src/core/crypto/sha3.cpp
    src/core/crypto/aes_gcm.cpp
    src/core/crypto/argon2.cpp
    src/core/crypto/dilithium.cpp
    src/core/crypto/bignum.cpp
    src/core/crypto/rsa_pss.cpp
    src/core/crypto/ecdsa.cpp
    src/core/crypto/x448.cpp
    src/core/crypto/sha256.cpp
    src/core/crypto/hmac_sha256.cpp
    src/core/crypto/hmac_sha512.cpp
    src/core/crypto/hkdf_sha256.cpp
    src/core/crypto/hkdf_sha512.cpp
    src/core/crypto/blake2b.cpp
    src/core/crypto/pbkdf2_hmac_sha256.cpp
    src/core/crypto/scrypt.cpp
    src/core/crypto/hmac_drbg.cpp
    src/core/crypto/secure_random.cpp
    src/core/crypto/aes_key_wrap.cpp
    src/core/crypto/shamir_secret_sharing.cpp
    src/core/crypto/x3dh.cpp
    src/core/crypto/pq_x3dh.cpp
    src/core/crypto/schnorr.cpp
    src/core/crypto/shake.cpp
    src/core/crypto/hd_keys.cpp
    src/core/crypto/ecies.cpp
    src/core/crypto/oprf.cpp
    src/core/crypto/vdf.cpp
    src/core/crypto/xchacha20.cpp
    src/core/crypto/double_ratchet.cpp
    src/core/crypto/osnova_handshake.cpp
    src/core/crypto/srp6a.cpp
    # Mesh Layer
    src/core/mesh/kvm_clock.cpp
    src/core/mesh/mesh_node.cpp
    src/core/mesh/dtn_router.cpp
    src/core/mesh/packet_processor.cpp
    # Net Layer
    src/core/net/multiplexer.cpp
    src/core/net/quic_session.cpp
    src/core/net/kcp_session.cpp
    src/core/net/bbr_congestion.cpp
    src/core/net/hpack.cpp
    src/core/net/onion_router.cpp
    src/core/net/rabin_cdc.cpp
    src/core/net/sip_stack.cpp
    src/core/net/stun_client.cpp
    src/core/net/turn_client.cpp
    src/core/net/ice_agent.cpp
    src/core/net/udp_transport.cpp
    src/core/net/tcp_transport.cpp
    # DS Layer
    src/core/ds/bloom_filter.cpp
    src/core/ds/cuckoo_filter.cpp
    src/core/ds/merkle_mtrie.cpp
    src/core/ds/hyperloglog.cpp
    src/core/ds/crdt_map.cpp
    src/core/ds/adaptive_radix_tree.cpp
    src/core/ds/ring_buffer.cpp
    src/core/ds/skip_list.cpp
    # DSP Layer
    src/core/dsp/fec_engine.cpp
    src/core/dsp/reed_solomon.cpp
    src/core/dsp/afsk_modulator.cpp
    src/core/dsp/audio_modem.cpp
)

target_include_directories(nit_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# target_link_libraries(nit_core PUBLIC Threads::Threads asio SQLite::SQLite3)

# ==============================================================================
# Subdirectories
# ==============================================================================
# add_subdirectory(server)
# add_subdirectory(ui)
# add_subdirectory(mobile_bridges)
