#ifndef GREENTLS_EXTENSIONS_HPP
#define GREENTLS_EXTENSIONS_HPP

#include <cstdint>
#include <cstdlib>

struct SignatureAlgorithmsRecord {
    uint8_t count;
    uint16_t algorithms[16];
};

#if defined(__cplusplus)
extern "C" {
#endif

extern void parseSignatureAlgorithms(const uint8_t*, size_t, SignatureAlgorithmsRecord**);

#if defined(__cplusplus)
}
#endif

#endif
