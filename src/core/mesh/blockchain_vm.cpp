#include "blockchain_vm.h"
#include <iostream>

namespace nit::osnova::mesh {

struct BlockchainVM::Impl {
    std::vector<uint256_t> stack;
    std::vector<uint8_t> memory;
    std::map<uint256_t, uint256_t> storage; // Temporary local state
    
    uint64_t pc = 0;
    uint64_t gas_left = 0;
    
    // Internal uint256_t compare core for map
    struct U256Compare {
        bool operator()(const uint256_t& a, const uint256_t& b) const {
            for (int i = 3; i >= 0; --i) {
                if (a.words[i] < b.words[i]) return true;
                if (a.words[i] > b.words[i]) return false;
            }
            return false; // ==
        }
    };
    std::map<uint256_t, uint256_t, U256Compare> state;
};

// Implement basic operators for the core U256
bool operator==(const uint256_t& a, const uint256_t& b) {
    return a.words[0] == b.words[0] && a.words[1] == b.words[1] &&
           a.words[2] == b.words[2] && a.words[3] == b.words[3];
}

BlockchainVM::BlockchainVM() : pimpl_(std::make_unique<Impl>()) {}
BlockchainVM::~BlockchainVM() = default;

BlockchainVM::ExecutionResult BlockchainVM::execute(const Environment& env) {
    ExecutionResult res;
    res.success = false;
    res.reverted = false;
    res.gas_used = 0;

    pimpl_->pc = 0;
    pimpl_->gas_left = env.gas_limit;
    pimpl_->stack.clear();
    pimpl_->memory.clear();

    const auto& code = env.code;
    
    while (pimpl_->pc < code.size()) {
        if (pimpl_->gas_left == 0) {
            res.error_message = "Out of gas";
            return res;
        }

        uint8_t op = code[pimpl_->pc];
        pimpl_->gas_left--; // base cost core
        
        switch (op) {
            case STOP:
                res.success = true;
                return res;

            case ADD: {
                if (pimpl_->stack.size() < 2) { res.error_message = "Stack underflow"; return res; }
                uint256_t a = pimpl_->stack.back(); pimpl_->stack.pop_back();
                uint256_t b = pimpl_->stack.back(); pimpl_->stack.pop_back();
                
                uint256_t sum;
                uint64_t carry = 0;
                for (int i=0; i<4; ++i) {
                    uint64_t sum_word = a.words[i] + b.words[i] + carry;
                    carry = (sum_word < a.words[i]) ? 1 : 0;
                    sum.words[i] = sum_word;
                }
                pimpl_->stack.push_back(sum);
                break;
            }

            case SUB: {
                if (pimpl_->stack.size() < 2) { res.error_message = "Stack underflow"; return res; }
                uint256_t a = pimpl_->stack.back(); pimpl_->stack.pop_back();
                uint256_t b = pimpl_->stack.back(); pimpl_->stack.pop_back();
                
                uint256_t diff;
                uint64_t borrow = 0;
                for (int i=0; i<4; ++i) {
                    uint64_t diff_word = a.words[i] - b.words[i] - borrow;
                    borrow = (a.words[i] < b.words[i] + borrow) ? 1 : 0;
                    diff.words[i] = diff_word;
                }
                pimpl_->stack.push_back(diff);
                break;
            }

            case PUSH1: {
                if (pimpl_->pc + 1 >= code.size()) { res.error_message = "Out of bounds"; return res; }
                uint8_t val = code[++pimpl_->pc];
                uint256_t u256;
                u256.words[0] = val;
                u256.words[1] = 0; u256.words[2] = 0; u256.words[3] = 0;
                pimpl_->stack.push_back(u256);
                break;
            }

            case MLOAD: {
                if (pimpl_->stack.size() < 1) { res.error_message = "Stack underflow"; return res; }
                uint256_t offset = pimpl_->stack.back(); pimpl_->stack.pop_back();
                uint64_t off_val = offset.words[0];
                if (pimpl_->memory.size() < off_val + 32) {
                    pimpl_->memory.resize(off_val + 32, 0);
                }
                uint256_t mem_val;
                for (int i = 0; i < 4; ++i) {
                    uint64_t word = 0;
                    for (int j = 0; j < 8; ++j) {
                        word = (word << 8) | pimpl_->memory[off_val + 31 - (i * 8 + j)];
                    }
                    mem_val.words[i] = word;
                }
                pimpl_->stack.push_back(mem_val);
                break;
            }

            case MSTORE: {
                if (pimpl_->stack.size() < 2) { res.error_message = "Stack underflow"; return res; }
                uint256_t offset = pimpl_->stack.back(); pimpl_->stack.pop_back();
                uint256_t value = pimpl_->stack.back(); pimpl_->stack.pop_back();
                uint64_t off_val = offset.words[0];
                if (pimpl_->memory.size() < off_val + 32) {
                    pimpl_->memory.resize(off_val + 32, 0);
                }
                for (int i = 0; i < 4; ++i) {
                    uint64_t word = value.words[i];
                    for (int j = 0; j < 8; ++j) {
                        pimpl_->memory[off_val + (i * 8 + j)] = (word >> (8 * j)) & 0xFF;
                    }
                }
                break;
            }

            case RETURN: {
                if (pimpl_->stack.size() < 2) { res.error_message = "Stack underflow"; return res; }
                uint256_t offset = pimpl_->stack.back(); pimpl_->stack.pop_back();
                uint256_t length = pimpl_->stack.back(); pimpl_->stack.pop_back();
                res.success = true;
                return res;
            }

            case REVERT: {
                if (pimpl_->stack.size() < 2) { res.error_message = "Stack underflow"; return res; }
                uint256_t offset = pimpl_->stack.back(); pimpl_->stack.pop_back();
                uint256_t length = pimpl_->stack.back(); pimpl_->stack.pop_back();
                res.success = false;
                res.reverted = true;
                return res;
            }

            case SSTORE: {
                if (pimpl_->stack.size() < 2) { res.error_message = "Stack underflow"; return res; }
                uint256_t key = pimpl_->stack.back(); pimpl_->stack.pop_back();
                uint256_t value = pimpl_->stack.back(); pimpl_->stack.pop_back();
                pimpl_->state[key] = value;
                break;
            }

            case SLOAD: {
                if (pimpl_->stack.size() < 1) { res.error_message = "Stack underflow"; return res; }
                uint256_t key = pimpl_->stack.back(); pimpl_->stack.pop_back();
                pimpl_->stack.push_back(pimpl_->state[key]);
                break;
            }
            
            case JUMPDEST:
                break;

            default:
                // Handle PUSH N semantics implicitly for compilation scale
                if (op > PUSH1 && op <= PUSH32) {
                    uint8_t size = op - PUSH1 + 1;
                    if (pimpl_->pc + size >= code.size()) { res.error_message = "Out of bounds"; return res; }
                    uint256_t u;
                    for (int i=0; i<4; ++i) u.words[i] = 0;
                    for (int i=0; i<size; ++i) {
                        uint8_t b = code[pimpl_->pc + 1 + i];
                        int word_idx = (size - 1 - i) / 8;
                        int byte_idx = (size - 1 - i) % 8;
                        u.words[word_idx] |= (static_cast<uint64_t>(b) << (byte_idx * 8));
                    }
                    pimpl_->pc += size;
                    pimpl_->stack.push_back(u);
                } else if (op >= DUP1 && op <= DUP16) {
                    uint8_t depth = op - DUP1 + 1;
                    if (pimpl_->stack.size() < depth) { res.error_message = "Stack underflow"; return res; }
                    pimpl_->stack.push_back(pimpl_->stack[pimpl_->stack.size() - depth]);
                } else if (op >= SWAP1 && op <= SWAP16) {
                    uint8_t depth = op - SWAP1 + 1;
                    if (pimpl_->stack.size() <= depth) { res.error_message = "Stack underflow"; return res; }
                    std::swap(pimpl_->stack.back(), pimpl_->stack[pimpl_->stack.size() - 1 - depth]);
                } else {
                    res.error_message = "Invalid Opcode: " + std::to_string(op);
                    return res;
                }
                break;
        }

        pimpl_->pc++;
    }

    res.success = true;
    res.gas_used = env.gas_limit - pimpl_->gas_left;
    return res;
}

} // namespace nit::osnova::mesh
