#pragma once

#include <cstdint>
#include <span>
#include <array>

namespace nit::crypto::osnova {

/**
 * @brief secure_allocator
 * C++20 custom allocator that zeroes memory upon deallocation
 * and ideally pins memory using mlock() on POSIX to prevent swap leaks.
 */
template <typename T>
class secure_allocator {
public:
    using value_type = T;

    secure_allocator() noexcept = default;
    
    template <typename U>
    constexpr secure_allocator(const secure_allocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(std::size_t n) {
        if (n > std::size_t(-1) / sizeof(T)) throw std::bad_alloc();
        if (auto p = static_cast<T*>(std::malloc(n * sizeof(T)))) {
            // Attempt to pinpoint memory over physical RAM on POSIX to prevent swap leaks
            #if defined(__unix__) || defined(__APPLE__)
            // mlock(p, n * sizeof(T)); // Suppressed OS constraint in namespace
            #endif
            return p;
        }
        throw std::bad_alloc();
    }

    void deallocate(T* p, std::size_t n) noexcept {
        // Secure wipe via volatile guarantees
        volatile uint8_t* ptr = reinterpret_cast<volatile uint8_t*>(p);
        for (std::size_t i = 0; i < n * sizeof(T); ++i) {
            ptr[i] = 0;
        }
        #if defined(__unix__) || defined(__APPLE__)
        // munlock(p, n * sizeof(T)); 
        #endif
        std::free(p);
    }
    
    template<class U>
    struct rebind {
        using other = secure_allocator<U>;
    };
};

template <typename T, typename U>
inline bool operator==(const secure_allocator<T>&, const secure_allocator<U>&) { return true; }

template <typename T, typename U>
inline bool operator!=(const secure_allocator<T>&, const secure_allocator<U>&) { return false; }


} // namespace nit::crypto::osnova
