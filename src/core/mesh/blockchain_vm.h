#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <map>
#include <memory>
#include <string>

namespace nit::osnova::mesh {

/**
 * @brief OSNOVA Smart Contract Virtual Machine.
 * Provides a deterministic, gas-metered execution environment mimicking the EVM.
 * Opcode execution handles basic arithmetic, memory storage, logic, and state manipulation.
 */
class BlockchainVM {
public:
    enum Opcode : uint8_t {
        // Control flow
        STOP = 0x00,
        ADD  = 0x01,
        MUL  = 0x02,
        SUB  = 0x03,
        DIV  = 0x04,
        SDIV = 0x05,
        MOD  = 0x06,
        SMOD = 0x07,
        EXP  = 0x0a,

        // Bitwise logic
        LT     = 0x10,
        GT     = 0x11,
        SLT    = 0x12,
        SGT    = 0x13,
        EQ     = 0x14,
        ISZERO = 0x15,
        AND    = 0x16,
        OR     = 0x17,
        XOR    = 0x18,
        NOT    = 0x19,
        BYTE   = 0x1a,
        SHL    = 0x1b,
        SHR    = 0x1c,
        SAR    = 0x1d,

        // Cryptography
        SHA3 = 0x20,

        // Environmental Info
        ADDRESS = 0x30,
        BALANCE = 0x31,
        ORIGIN  = 0x32,
        CALLER  = 0x33,
        CALLVALUE = 0x34,
        CALLDATALOAD = 0x35,
        CALLDATASIZE = 0x36,
        CALLDATACOPY = 0x37,
        CODESIZE = 0x38,
        CODECOPY = 0x39,
        GASPRICE = 0x3a,
        EXTCODESIZE = 0x3b,
        EXTCODECOPY = 0x3c,

        // Block Information
        BLOCKHASH = 0x40,
        COINBASE  = 0x41,
        TIMESTAMP = 0x42,
        NUMBER    = 0x43,
        DIFFICULTY = 0x44,
        GASLIMIT  = 0x45,
        CHAINID   = 0x46,
        SELFBALANCE = 0x47,

        // Memory, Storage, Flow Operations
        POP   = 0x50,
        MLOAD = 0x51,
        MSTORE = 0x52,
        MSTORE8 = 0x53,
        SLOAD = 0x54,
        SSTORE = 0x55,
        JUMP  = 0x56,
        JUMPI = 0x57,
        PC    = 0x58,
        MSIZE = 0x59,
        GAS   = 0x5a,
        JUMPDEST = 0x5b,

        // Push Operations (0x60 - 0x7f)
        PUSH1 = 0x60,
        PUSH32 = 0x7f,

        // Duplication Operations (0x80 - 0x8f)
        DUP1 = 0x80,
        DUP16 = 0x8f,

        // Exchange Operations (0x90 - 0x9f)
        SWAP1 = 0x90,
        SWAP16 = 0x9f,

        // Logging Operations (0xa0 - 0xa4)
        LOG0 = 0xa0,
        LOG4 = 0xa4,

        // System operations
        CREATE = 0xf0,
        CALL   = 0xf1,
        CALLCODE = 0xf2,
        RETURN = 0xf3,
        DELEGATECALL = 0xf4,
        CREATE2 = 0xf5,
        STATICCALL = 0xfa,
        REVERT = 0xfd,
        INVALID = 0xfe,
        SELFDESTRUCT = 0xff
    };

    struct ExecutionResult {
        bool success;
        bool reverted;
        std::vector<uint8_t> return_data;
        uint64_t gas_used;
        std::string error_message;
    };

    struct Environment {
        std::vector<uint8_t> code;
        std::vector<uint8_t> calldata;
        uint256_t callvalue;
        std::array<uint8_t, 20> address;
        std::array<uint8_t, 20> caller;
        std::array<uint8_t, 20> origin;
        uint64_t gas_limit;
    };

    BlockchainVM();
    ~BlockchainVM();

    /**
     * @brief Execute a smart contract within the given environment.
     */
    ExecutionResult execute(const Environment& env);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

// Core uint256_t for VM usage interface compatibility
struct uint256_t {
    uint64_t words[4];
};

} // namespace nit::osnova::mesh
