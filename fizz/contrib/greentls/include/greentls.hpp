#ifndef GREENTLS_HPP
#define GREENTLS_HPP

#define MAX_EXTENSIONS 16
#define MAX_CERTIFICATES 8

#include <cstdint>
#include <cstdlib>

struct RecordRecord {
    bool valid_plaintext;
    bool valid_ciphertext;
    uint8_t content_type;
    uint16_t length;
};

struct ExtensionRecord {
    uint16_t type;
    uint16_t length;
    uint32_t offset;
};

struct ClientHelloRecord {
    uint8_t random[32];
    uint8_t legacy_session_id_length;
    uint8_t legacy_session_id[256];
    uint8_t cipher_suites_count;
    uint16_t cipher_suites[4];
    uint8_t extensions_count;
    ExtensionRecord extensions[MAX_EXTENSIONS];
};

struct ServerHelloRecord {
    uint8_t random[32];
    uint8_t legacy_session_id_length;
    uint8_t legacy_session_id[256];
    uint16_t cipher_suite;
    uint8_t extensions_count;
    ExtensionRecord extensions[MAX_EXTENSIONS];
};

struct EncryptedExtensionsRecord {
    uint8_t extensions_count;
    ExtensionRecord extensions[MAX_EXTENSIONS];
};

struct CertificateEntryRecord {
    uint32_t length;
    uint32_t offset;
    uint8_t extensions_count;
    ExtensionRecord extensions[MAX_EXTENSIONS];
};

struct CertificateRecord {
    uint32_t certificate_request_context_length;
    uint32_t certificate_request_context_offset;
    uint8_t certificates_count;
    CertificateEntryRecord certificates[MAX_CERTIFICATES];
};

struct CertificateRequestRecord {
    uint32_t certificate_request_context_length;
    uint32_t certificate_request_context_offset;
    uint8_t extensions_count;
    ExtensionRecord extensions[MAX_EXTENSIONS];
};

struct CertificateVerifyRecord {
    uint16_t signature_scheme;
    uint32_t signature_length;
    uint32_t signature_offset;
};

struct FinishedRecord {
    uint32_t verify_data_length;
    uint32_t verify_data_offset;
};

struct NewSessionTicketRecord {
    uint32_t ticket_lifetime;
    uint32_t ticket_age_add;
    uint32_t ticket_nonce_length;
    uint32_t ticket_nonce_offset;
    uint32_t ticket_length;
    uint32_t ticket_offset;
    uint8_t extensions_count;
    ExtensionRecord extensions[MAX_EXTENSIONS];
};

struct KeyUpdateRecord {
    uint8_t request_update;
};

union HandshakeVariants {
    ClientHelloRecord client_hello;
    ServerHelloRecord server_hello;
    EncryptedExtensionsRecord encrypted_extensions;
    CertificateRecord certificate;
    CertificateRequestRecord certificate_request;
    CertificateVerifyRecord certificate_verify;
    FinishedRecord finished;
    NewSessionTicketRecord new_session_ticket;
    KeyUpdateRecord key_update;
};

struct HandshakeRecord {
    uint8_t tag;
    HandshakeVariants content;
};

struct AlertRecord {
    uint8_t level;
    uint8_t description;
};

#if defined(__cplusplus)
extern "C" {
#endif

extern void parseRecordMessage(const uint8_t*, size_t, RecordRecord**);
extern void parseHandshakeMessage(const uint8_t*, size_t, HandshakeRecord**);
extern void parseAlertMessage(const uint8_t*, size_t, AlertRecord**);

#if defined(__cplusplus)
}
#endif

#endif
