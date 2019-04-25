#ifndef GREENTLS_EXTENSIONS_HPP
#define GREENTLS_EXTENSIONS_HPP

#include <cstdint>
#include <cstdlib>

struct SignatureAlgorithmsRecord {
    uint8_t count;
    uint16_t algorithms[16];
};

struct SupportedGroupsRecord {
    uint8_t count;
    uint16_t groups[16];
};

#if defined(__cplusplus)
extern "C" {
#endif

extern void parseSignatureAlgorithms(const uint8_t*, size_t, SignatureAlgorithmsRecord**);
extern void parseSupportedGroups(const uint8_t*, size_t, SupportedGroupsRecord**);

#if defined(__cplusplus)
}
#endif

#endif
