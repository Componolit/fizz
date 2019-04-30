/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <vector>

#include <fizz/record/Types.h>

#include "greentls_extensions.hpp"

namespace fizz {

inline std::vector<Extension>::const_iterator findExtension(
    const std::vector<Extension>& extensions,
    ExtensionType type) {
  for (auto it = extensions.begin(); it != extensions.end(); ++it) {
    if (it->extension_type == type) {
      return it;
    }
  }
  return extensions.end();
}

template <class T>
inline folly::Optional<T> getExtension(
    const std::vector<Extension>& extensions) {
  auto it = findExtension(extensions, T::extension_type);
  if (it == extensions.end()) {
    return folly::none;
  }
  folly::io::Cursor cs{it->extension_data.get()};
  auto ret = getExtension<T>(cs);
  if (!cs.isAtEnd()) {
    throw std::runtime_error("didn't read entire extension");
  }
  return ret;
}

template <>
inline SignatureAlgorithms getExtension(folly::io::Cursor& cs) {
  Buf buf;
  cs.cloneAtMost(buf, 65536);

  std::unique_ptr<SignatureAlgorithmsRecord> recordPtr(new SignatureAlgorithmsRecord());
  SignatureAlgorithmsRecord *record = recordPtr.get();
  parseSignatureAlgorithms(buf->data(), buf->length(), &record);

  if (record->count == 0) {
    throw FizzException("invalid signature algorithms extension", AlertDescription::decode_error);
  }

  SignatureAlgorithms sigs;
  for (size_t i = 0; i < record->count; i++) {
    sigs.supported_signature_algorithms.push_back(SignatureScheme(record->algorithms[i]));
  }
  return sigs;
}

template <>
inline SupportedGroups getExtension(folly::io::Cursor& cs) {
  Buf buf;
  cs.cloneAtMost(buf, 65536);

  std::unique_ptr<SupportedGroupsRecord> recordPtr(new SupportedGroupsRecord());
  SupportedGroupsRecord *record = recordPtr.get();
  parseSupportedGroups(buf->data(), buf->length(), &record);

  if (record->count == 0) {
    throw FizzException("invalid supported groups extension", AlertDescription::decode_error);
  }

  SupportedGroups groups;
  for (size_t i = 0; i < record->count; i++) {
    groups.named_group_list.push_back(NamedGroup(record->groups[i]));
  }
  return groups;
}

template <>
inline ClientKeyShare getExtension(folly::io::Cursor& cs) {
  Buf buf;
  cs.cloneAtMost(buf, 4294967296);
  if (buf->isChained()) {
    buf->coalesce();
  }

  std::unique_ptr<ClientKeyShareRecord> recordPtr(new ClientKeyShareRecord());
  ClientKeyShareRecord *record = recordPtr.get();
  parseClientKeyShare(buf->data(), buf->length(), &record);

  if (!record->valid) {
    throw FizzException("invalid key share extension (CH)", AlertDescription::decode_error);
  }

  ClientKeyShare share;
  for (size_t i = 0; i < record->count; i++) {
    share.client_shares.push_back(
      KeyShareEntry{
        NamedGroup(record->shares[i].group),
        cloneIntoBuf(buf, record->shares[i].key_exchange_offset, record->shares[i].key_exchange_length)});
  }
  return share;
}

template <>
inline ServerKeyShare getExtension(folly::io::Cursor& cs) {
  Buf buf;
  cs.cloneAtMost(buf, 4294967296);
  if (buf->isChained()) {
    buf->coalesce();
  }

  std::unique_ptr<ServerKeyShareRecord> recordPtr(new ServerKeyShareRecord());
  ServerKeyShareRecord *record = recordPtr.get();
  parseServerKeyShare(buf->data(), buf->length(), &record);

  if (!record->valid) {
    throw FizzException("invalid key share extension (SH)", AlertDescription::decode_error);
  }

  ServerKeyShare share{
    NamedGroup(record->share.group),
    cloneIntoBuf(buf, record->share.key_exchange_offset, record->share.key_exchange_length)};
  return share;
}

template <>
inline HelloRetryRequestKeyShare getExtension(folly::io::Cursor& cs) {
  Buf buf;
  cs.cloneAtMost(buf, 4294967296);
  if (buf->isChained()) {
    buf->coalesce();
  }

  std::unique_ptr<HelloRetryRequestKeyShareRecord> recordPtr(new HelloRetryRequestKeyShareRecord());
  HelloRetryRequestKeyShareRecord *record = recordPtr.get();
  parseHelloRetryRequestKeyShare(buf->data(), buf->length(), &record);

  if (!record->valid) {
    throw FizzException("invalid key share extension (HRR)", AlertDescription::decode_error);
  }

  HelloRetryRequestKeyShare share{
    NamedGroup(record->selected_group)};
  return share;
}

template <>
inline ClientPresharedKey getExtension(folly::io::Cursor& cs) {
  Buf buf;
  cs.cloneAtMost(buf, 4294967296);
  if (buf->isChained()) {
    buf->coalesce();
  }

  std::unique_ptr<ClientPresharedKeyRecord> recordPtr(new ClientPresharedKeyRecord());
  ClientPresharedKeyRecord *record = recordPtr.get();
  parseClientPresharedKey(buf->data(), buf->length(), &record);

  if (!record->valid) {
    throw FizzException("invalid pre-shared key extension (CH)", AlertDescription::decode_error);
  }

  ClientPresharedKey share;
  for (size_t i = 0; i < record->identity_count; i++) {
    share.identities.push_back(
      PskIdentity{
        cloneIntoBuf(buf, record->identities[i].identity_offset, record->identities[i].identity_length),
        record->identities[i].obfuscated_ticket_age});
  }
  for (size_t i = 0; i < record->binder_count; i++) {
    share.binders.push_back(
      PskBinder{
        cloneIntoBuf(buf, record->binders[i].binder_offset, record->binders[i].binder_length)});
  }
  return share;
}

template <>
inline ServerPresharedKey getExtension(folly::io::Cursor& cs) {
  Buf buf;
  cs.cloneAtMost(buf, 4);
  if (buf->isChained()) {
    buf->coalesce();
  }

  std::unique_ptr<ServerPresharedKeyRecord> recordPtr(new ServerPresharedKeyRecord());
  ServerPresharedKeyRecord *record = recordPtr.get();
  parseServerPresharedKey(buf->data(), buf->length(), &record);

  if (!record->valid) {
    throw FizzException("invalid pre-shared key extension (SH)", AlertDescription::decode_error);
  }

  ServerPresharedKey share;
  share.selected_identity = record->selected_identity;
  return share;
}

template <>
inline ClientEarlyData getExtension(folly::io::Cursor& /* unused */) {
  return ClientEarlyData();
}

template <>
inline ServerEarlyData getExtension(folly::io::Cursor& /* unused */) {
  return ServerEarlyData();
}

template <>
inline TicketEarlyData getExtension(folly::io::Cursor& cs) {
  Buf buf;
  cs.cloneAtMost(buf, 4);
  if (buf->isChained()) {
    buf->coalesce();
  }

  std::unique_ptr<EarlyDataIndicationRecord> recordPtr(new EarlyDataIndicationRecord());
  EarlyDataIndicationRecord *record = recordPtr.get();
  parseEarlyDataIndication(buf->data(), buf->length(), &record);

  if (!record->valid) {
    throw FizzException("invalid early data extension", AlertDescription::decode_error);
  }

  TicketEarlyData early;
  early.max_early_data_size = record->max_early_data_size;
  return early;
}

template <>
inline Cookie getExtension(folly::io::Cursor& cs) {
  Buf buf;
  cs.cloneAtMost(buf, 65536);
  if (buf->isChained()) {
    buf->coalesce();
  }

  std::unique_ptr<CookieRecord> recordPtr(new CookieRecord());
  CookieRecord *record = recordPtr.get();
  parseCookie(buf->data(), buf->length(), &record);

  if (record->offset == 0 && record->length == 0) {
    throw FizzException("invalid cookie extension", AlertDescription::decode_error);
  }

  Cookie cookie;
  cookie.cookie = cloneIntoBuf(buf, record->offset, record->length);
  return cookie;
}

template <>
inline SupportedVersions getExtension(folly::io::Cursor& cs) {
  Buf buf;
  cs.cloneAtMost(buf, 256);
  if (buf->isChained()) {
    buf->coalesce();
  }

  std::unique_ptr<SupportedVersionsRecord> recordPtr(new SupportedVersionsRecord());
  SupportedVersionsRecord *record = recordPtr.get();
  parseSupportedVersions(buf->data(), buf->length(), &record);

  if (record->count == 0) {
    throw FizzException("invalid supported versions extension (CH)", AlertDescription::decode_error);
  }

  SupportedVersions versions;
  for (size_t i = 0; i < record->count; i++) {
    versions.versions.push_back(
      ProtocolVersion(record->versions[i]));
  }
  return versions;
}

template <>
inline ServerSupportedVersions getExtension(folly::io::Cursor& cs) {
  Buf buf;
  cs.cloneAtMost(buf, 4);
  if (buf->isChained()) {
    buf->coalesce();
  }

  std::unique_ptr<SupportedVersionRecord> recordPtr(new SupportedVersionRecord());
  SupportedVersionRecord *record = recordPtr.get();
  parseSupportedVersion(buf->data(), buf->length(), &record);

  if (record->version == 0) {
    throw FizzException("invalid supported versions extension (SH)", AlertDescription::decode_error);
  }

  ServerSupportedVersions versions;
  versions.selected_version = ProtocolVersion(record->version);
  return versions;
}

template <>
inline PskKeyExchangeModes getExtension(folly::io::Cursor& cs) {
  Buf buf;
  cs.cloneAtMost(buf, 256);
  if (buf->isChained()) {
    buf->coalesce();
  }

  std::unique_ptr<PskKeyExchangeModesRecord> recordPtr(new PskKeyExchangeModesRecord());
  PskKeyExchangeModesRecord *record = recordPtr.get();
  parsePskKeyExchangeModes(buf->data(), buf->length(), &record);

  if (record->count == 0) {
    throw FizzException("invalid psk key exchange modes extension", AlertDescription::decode_error);
  }

  PskKeyExchangeModes modes;
  for (size_t i = 0; i < record->count; i++) {
    modes.modes.push_back(
      PskKeyExchangeMode(record->modes[i]));
  }
  return modes;
}

template <>
inline ProtocolNameList getExtension(folly::io::Cursor& cs) {
  Buf buf;
  cs.cloneAtMost(buf, 65536);
  if (buf->isChained()) {
    buf->coalesce();
  }

  std::unique_ptr<ProtocolNameListRecord> recordPtr(new ProtocolNameListRecord());
  ProtocolNameListRecord *record = recordPtr.get();
  parseProtocolNameList(buf->data(), buf->length(), &record);

  if (record->count == 0) {
    throw FizzException("invalid alpn extension", AlertDescription::decode_error);
  }

  ProtocolNameList names;
  for (size_t i = 0; i < record->count; i++) {
    names.protocol_name_list.push_back(
      ProtocolName{
        cloneIntoBuf(buf, record->protocol_names[i].offset, record->protocol_names[i].length)});
  }
  return names;
}

template <>
inline ServerNameList getExtension(folly::io::Cursor& cs) {
  Buf buf;
  cs.cloneAtMost(buf, 65536);
  if (buf->isChained()) {
    buf->coalesce();
  }

  std::unique_ptr<ServerNameListRecord> recordPtr(new ServerNameListRecord());
  ServerNameListRecord *record = recordPtr.get();
  parseServerNameList(buf->data(), buf->length(), &record);

  if (record->count == 0) {
    throw FizzException("invalid server name extension", AlertDescription::decode_error);
  }

  ServerNameList names;
  for (size_t i = 0; i < record->count; i++) {
    names.server_name_list.push_back(
      ServerName{
        ServerNameType::host_name,
        cloneIntoBuf(buf, record->server_names[i].offset, record->server_names[i].length)});
  }
  return names;
}

template <>
inline CertificateAuthorities getExtension(folly::io::Cursor& cs) {
  CertificateAuthorities authorities;
  detail::readVector<uint16_t>(authorities.authorities, cs);
  return authorities;
}

template <>
inline CertificateCompressionAlgorithms getExtension(folly::io::Cursor& cs) {
  CertificateCompressionAlgorithms cca;
  detail::readVector<uint8_t>(cca.algorithms, cs);
  return cca;
}

template <>
inline Extension encodeExtension(const SignatureAlgorithms& sig) {
  Extension ext;
  ext.extension_type = ExtensionType::signature_algorithms;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::writeVector<uint16_t>(sig.supported_signature_algorithms, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const SupportedGroups& groups) {
  Extension ext;
  ext.extension_type = ExtensionType::supported_groups;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::writeVector<uint16_t>(groups.named_group_list, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const ClientKeyShare& share) {
  Extension ext;
  ext.extension_type = ExtensionType::key_share;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::writeVector<uint16_t>(share.client_shares, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const ServerKeyShare& share) {
  Extension ext;
  ext.extension_type = ExtensionType::key_share;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::write(share.server_share, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const HelloRetryRequestKeyShare& share) {
  Extension ext;
  ext.extension_type = ExtensionType::key_share;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::write(share.selected_group, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const ClientPresharedKey& share) {
  Extension ext;
  ext.extension_type = ExtensionType::pre_shared_key;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::writeVector<uint16_t>(share.identities, appender);
  detail::writeVector<uint16_t>(share.binders, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const ServerPresharedKey& share) {
  Extension ext;
  ext.extension_type = ExtensionType::pre_shared_key;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::write(share.selected_identity, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const ClientEarlyData&) {
  Extension ext;
  ext.extension_type = ExtensionType::early_data;
  ext.extension_data = folly::IOBuf::create(0);
  return ext;
}

template <>
inline Extension encodeExtension(const ServerEarlyData&) {
  Extension ext;
  ext.extension_type = ExtensionType::early_data;
  ext.extension_data = folly::IOBuf::create(0);
  return ext;
}

template <>
inline Extension encodeExtension(const TicketEarlyData& early) {
  Extension ext;
  ext.extension_type = ExtensionType::early_data;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::write(early.max_early_data_size, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const Cookie& cookie) {
  Extension ext;
  ext.extension_type = ExtensionType::cookie;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::writeBuf<uint16_t>(cookie.cookie, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const SupportedVersions& versions) {
  Extension ext;
  ext.extension_type = ExtensionType::supported_versions;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::writeVector<uint8_t>(versions.versions, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const ServerSupportedVersions& versions) {
  Extension ext;
  ext.extension_type = ExtensionType::supported_versions;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::write(versions.selected_version, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const PskKeyExchangeModes& modes) {
  Extension ext;
  ext.extension_type = ExtensionType::psk_key_exchange_modes;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::writeVector<uint8_t>(modes.modes, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const ProtocolNameList& names) {
  Extension ext;
  ext.extension_type = ExtensionType::application_layer_protocol_negotiation;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::writeVector<uint16_t>(names.protocol_name_list, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const ServerNameList& names) {
  Extension ext;
  ext.extension_type = ExtensionType::server_name;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::writeVector<uint16_t>(names.server_name_list, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const CertificateAuthorities& authorities) {
  Extension ext;
  ext.extension_type = ExtensionType::certificate_authorities;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::writeVector<uint16_t>(authorities.authorities, appender);
  return ext;
}

template <>
inline Extension encodeExtension(const CertificateCompressionAlgorithms& cca) {
  Extension ext;
  ext.extension_type = ExtensionType::compress_certificate;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::writeVector<uint8_t>(cca.algorithms, appender);
  return ext;
}

inline size_t getBinderLength(const ClientHello& chlo) {
  if (chlo.extensions.empty() ||
      chlo.extensions.back().extension_type != ExtensionType::pre_shared_key) {
    throw FizzException(
        "psk not at end of client hello", AlertDescription::decode_error);
  }
  folly::io::Cursor cursor(chlo.extensions.back().extension_data.get());
  uint16_t identitiesLen;
  detail::read(identitiesLen, cursor);
  cursor.skip(identitiesLen);
  uint16_t binderLen;
  detail::read(binderLen, cursor);
  if (cursor.totalLength() != binderLen) {
    throw FizzException(
        "malformed binder length", AlertDescription::decode_error);
  }
  return sizeof(binderLen) + binderLen;
}

namespace detail {

template <>
struct Reader<KeyShareEntry> {
  template <class T>
  size_t read(KeyShareEntry& out, folly::io::Cursor& cursor) {
    size_t len = 0;
    len += detail::read(out.group, cursor);
    len += readBuf<uint16_t>(out.key_exchange, cursor);
    return len;
  }
};

template <>
struct Writer<KeyShareEntry> {
  template <class T>
  void write(const KeyShareEntry& share, folly::io::Appender& out) {
    detail::write(share.group, out);
    detail::writeBuf<uint16_t>(share.key_exchange, out);
  }
};

template <>
struct Sizer<KeyShareEntry> {
  template <class T>
  size_t getSize(const KeyShareEntry& share) {
    return sizeof(NamedGroup) + getBufSize<uint16_t>(share.key_exchange);
  }
};

template <>
struct Reader<PskIdentity> {
  template <class T>
  size_t read(PskIdentity& out, folly::io::Cursor& cursor) {
    size_t len = 0;
    len += readBuf<uint16_t>(out.psk_identity, cursor);
    len += detail::read(out.obfuscated_ticket_age, cursor);
    return len;
  }
};

template <>
struct Writer<PskIdentity> {
  template <class T>
  void write(const PskIdentity& ident, folly::io::Appender& out) {
    writeBuf<uint16_t>(ident.psk_identity, out);
    detail::write(ident.obfuscated_ticket_age, out);
  }
};

template <>
struct Sizer<PskIdentity> {
  template <class T>
  size_t getSize(const PskIdentity& ident) {
    return getBufSize<uint16_t>(ident.psk_identity) + sizeof(uint32_t);
  }
};

template <>
struct Reader<PskBinder> {
  template <class T>
  size_t read(PskBinder& out, folly::io::Cursor& cursor) {
    return readBuf<uint8_t>(out.binder, cursor);
  }
};

template <>
struct Writer<PskBinder> {
  template <class T>
  void write(const PskBinder& binder, folly::io::Appender& out) {
    writeBuf<uint8_t>(binder.binder, out);
  }
};

template <>
struct Sizer<PskBinder> {
  template <class T>
  size_t getSize(const PskBinder& binder) {
    return getBufSize<uint8_t>(binder.binder);
  }
};

template <>
struct Reader<ProtocolName> {
  template <class T>
  size_t read(ProtocolName& name, folly::io::Cursor& cursor) {
    return readBuf<uint8_t>(name.name, cursor);
  }
};

template <>
struct Writer<ProtocolName> {
  template <class T>
  void write(const ProtocolName& name, folly::io::Appender& out) {
    writeBuf<uint8_t>(name.name, out);
  }
};

template <>
struct Sizer<ProtocolName> {
  template <class T>
  size_t getSize(const ProtocolName& name) {
    return getBufSize<uint8_t>(name.name);
  }
};

template <>
struct Reader<ServerName> {
  template <class T>
  size_t read(ServerName& name, folly::io::Cursor& cursor) {
    size_t size = 0;
    size += detail::read(name.name_type, cursor);
    size += readBuf<uint16_t>(name.hostname, cursor);
    return size;
  }
};

template <>
struct Writer<ServerName> {
  template <class T>
  void write(const ServerName& name, folly::io::Appender& out) {
    detail::write(name.name_type, out);
    writeBuf<uint16_t>(name.hostname, out);
  }
};

template <>
struct Sizer<ServerName> {
  template <class T>
  size_t getSize(const ServerName& name) {
    return sizeof(ServerNameType) + getBufSize<uint16_t>(name.hostname);
  }
};

template <>
struct Reader<DistinguishedName> {
  template <class T>
  size_t read(DistinguishedName& dn, folly::io::Cursor& cursor) {
    return readBuf<uint16_t>(dn.encoded_name, cursor);
  }
};

template <>
struct Writer<DistinguishedName> {
  template <class T>
  void write(const DistinguishedName& dn, folly::io::Appender& out) {
    writeBuf<uint16_t>(dn.encoded_name, out);
  }
};

template <>
struct Sizer<DistinguishedName> {
  template <class T>
  size_t getSize(const DistinguishedName& dn) {
    return getBufSize<uint16_t>(dn.encoded_name);
  }
};
} // namespace detail
} // namespace fizz
