#pragma once

#include <vector>
#include <cstdint>
#include <memory>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief Yao's Garbled Circuits primitive.
 * Used for secure 2-party computation where Alice and Bob can compute a joint 
 * function on their private inputs without revealing the inputs to each other.
 * Integral for private OSNOVA group matching and intersection rules.
 */
class GarbledCircuit {
public:
    struct Gate {
        std::vector<uint8_t> table; // Encrypted truth table
    };

    struct CircuitContext {
        std::vector<Gate> gates;
        std::vector<std::vector<uint8_t>> input_wire_labels;
        std::vector<std::vector<uint8_t>> output_wire_labels;
    };

    /**
     * @brief Alice garbles the logical boolean circuit.
     */
    static CircuitContext garble_circuit();

    /**
     * @brief Bob evaluates the garbled circuit using labels obtained via Oblivious Transfer.
     */
    static std::vector<uint8_t> evaluate(const CircuitContext& ctx, const std::vector<std::vector<uint8_t>>& bob_wire_labels);
};

} // namespace nit::crypto::osnova
