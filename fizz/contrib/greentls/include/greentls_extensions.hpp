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

struct KeyShareEntryRecord {
    uint16_t group;
    uint16_t key_exchange_length;
    uint32_t key_exchange_offset;
};

struct ClientKeyShareRecord {
    bool valid;
    uint8_t count;
    KeyShareEntryRecord shares[16];
};

struct ServerKeyShareRecord {
    bool valid;
    KeyShareEntryRecord share;
};

struct HelloRetryRequestKeyShareRecord {
    bool valid;
    uint16_t selected_group;
};

#if defined(__cplusplus)
extern "C" {
#endif

extern void parseSignatureAlgorithms(const uint8_t*, size_t, SignatureAlgorithmsRecord**);
extern void parseSupportedGroups(const uint8_t*, size_t, SupportedGroupsRecord**);
extern void parseClientKeyShare(const uint8_t*, size_t, ClientKeyShareRecord**);
extern void parseServerKeyShare(const uint8_t*, size_t, ServerKeyShareRecord**);
extern void parseHelloRetryRequestKeyShare(const uint8_t*, size_t, HelloRetryRequestKeyShareRecord**);

#if defined(__cplusplus)
}
#endif

#endif
