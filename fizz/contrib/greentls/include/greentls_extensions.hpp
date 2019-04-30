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

struct PskIdentityRecord {
    uint16_t identity_length;
    uint32_t identity_offset;
    uint32_t obfuscated_ticket_age;
};

struct PskBinderEntryRecord {
    uint16_t binder_length;
    uint32_t binder_offset;
};

struct ClientPresharedKeyRecord {
    bool valid;
    uint8_t identity_count;
    PskIdentityRecord identities[16];
    uint8_t binder_count;
    PskBinderEntryRecord binders[16];
};

struct ServerPresharedKeyRecord {
    bool valid;
    uint16_t selected_identity;
};

struct EarlyDataIndicationRecord {
    bool valid;
    uint32_t max_early_data_size;
};

struct CookieRecord {
    uint16_t length;
    uint32_t offset;
};

struct SupportedVersionsRecord {
    uint8_t count;
    uint16_t versions[16];
};

struct SupportedVersionRecord {
    uint16_t version;
};

struct PskKeyExchangeModesRecord {
    uint8_t count;
    uint8_t modes[8];
};

struct ProtocolNameRecord {
    uint16_t length;
    uint32_t offset;
};

struct ProtocolNameListRecord {
    uint8_t count;
    ProtocolNameRecord protocol_names[8];
};

#if defined(__cplusplus)
extern "C" {
#endif

extern void parseSignatureAlgorithms(const uint8_t*, size_t, SignatureAlgorithmsRecord**);
extern void parseSupportedGroups(const uint8_t*, size_t, SupportedGroupsRecord**);
extern void parseClientKeyShare(const uint8_t*, size_t, ClientKeyShareRecord**);
extern void parseServerKeyShare(const uint8_t*, size_t, ServerKeyShareRecord**);
extern void parseHelloRetryRequestKeyShare(const uint8_t*, size_t, HelloRetryRequestKeyShareRecord**);
extern void parseClientPresharedKey(const uint8_t*, size_t, ClientPresharedKeyRecord**);
extern void parseServerPresharedKey(const uint8_t*, size_t, ServerPresharedKeyRecord**);
extern void parseEarlyDataIndication(const uint8_t*, size_t, EarlyDataIndicationRecord**);
extern void parseCookie(const uint8_t*, size_t, CookieRecord**);
extern void parseSupportedVersions(const uint8_t*, size_t, SupportedVersionsRecord**);
extern void parseSupportedVersion(const uint8_t*, size_t, SupportedVersionRecord**);
extern void parsePskKeyExchangeModes(const uint8_t*, size_t, PskKeyExchangeModesRecord**);
extern void parseProtocolNameList(const uint8_t*, size_t, ProtocolNameListRecord**);

#if defined(__cplusplus)
}
#endif

#endif
