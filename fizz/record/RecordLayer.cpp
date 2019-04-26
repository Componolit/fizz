/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/record/RecordLayer.h>

#include "greentls.hpp"

namespace fizz {

using HandshakeTypeType = typename std::underlying_type<HandshakeType>::type;

static constexpr size_t kHandshakeHeaderSize =
    sizeof(HandshakeType) + detail::bits24::size;

folly::Optional<Param> ReadRecordLayer::readEvent(
    folly::IOBufQueue& socketBuf) {
  if (!unparsedHandshakeData_.empty()) {
    auto param = decodeHandshakeMessage(unparsedHandshakeData_);
    if (param) {
      VLOG(8) << "Received handshake message "
              << toString(boost::apply_visitor(EventVisitor(), *param));
      return param;
    }
  }

  while (true) {
    // Read one record. We read one record at a time since records could cause
    // a change in the record layer.
    auto message = read(socketBuf);
    if (!message) {
      return folly::none;
    }

    if (!unparsedHandshakeData_.empty() &&
        message->type != ContentType::handshake) {
      throw std::runtime_error("spliced handshake data");
    }

    switch (message->type) {
      case ContentType::alert: {
        folly::io::Cursor cursor(message->fragment.get());
        auto alert = parseAlert(cursor);
        if (alert.description == AlertDescription::close_notify) {
          return Param(CloseNotify(socketBuf.move()));
        } else {
          return Param(std::move(alert));
        }
      }
      case ContentType::handshake: {
        unparsedHandshakeData_.append(std::move(message->fragment));
        auto param = decodeHandshakeMessage(unparsedHandshakeData_);
        if (param) {
          VLOG(8) << "Received handshake message "
                  << toString(boost::apply_visitor(EventVisitor(), *param));
          return param;
        } else {
          // If we read handshake data but didn't have enough to get a full
          // message we immediately try to read another record.
          // TODO: add limits on number of records we buffer
          continue;
        }
      }
      case ContentType::application_data:
        return Param(AppData(std::move(message->fragment)));
      default:
        throw std::runtime_error("unknown content type");
    }
  }
}

template <typename T>
static Param parse(Buf handshakeMsg, Buf original) {
  auto msg = decode<T>(std::move(handshakeMsg));
  msg.originalEncoding = std::move(original);
  return std::move(msg);
}

template <>
Param parse<ServerHello>(Buf handshakeMsg, Buf original) {
  auto shlo = decode<ServerHello>(std::move(handshakeMsg));
  if (shlo.random == HelloRetryRequest::HrrRandom) {
    HelloRetryRequest hrr;
    hrr.legacy_version = shlo.legacy_version;
    hrr.legacy_session_id_echo = std::move(shlo.legacy_session_id_echo);
    hrr.cipher_suite = shlo.cipher_suite;
    hrr.legacy_compression_method = shlo.legacy_compression_method;
    hrr.extensions = std::move(shlo.extensions);

    hrr.originalEncoding = std::move(original);
    return std::move(hrr);
  } else {
    shlo.originalEncoding = std::move(original);
    return std::move(shlo);
  }
}

std::vector<Extension> convertExtensions(Buf const& buf,
                                         uint8_t extensions_count,
                                         ExtensionRecord extensions[]) {
  std::vector<Extension> result;

  for (int i = 0; i < extensions_count; i++) {
    result.push_back(
      Extension{
        ExtensionType(extensions[i].type),
        cloneIntoBuf(buf, extensions[i].offset, extensions[i].length)});
  }

  return result;
}

Param convertClientHello(ClientHelloRecord *record, Buf coalesced, Buf original) {
    ClientHello chlo = ClientHello();

    std::copy(std::begin(record->random),
              std::end(record->random),
              std::begin(chlo.random));

    chlo.legacy_session_id = folly::IOBuf::copyBuffer(record->legacy_session_id,
                                                      record->legacy_session_id_length);

    for (int i = 0; i < record->cipher_suites_count; i++) {
        chlo.cipher_suites.push_back(CipherSuite(record->cipher_suites[i]));
    }

    chlo.legacy_compression_methods.push_back(0);

    chlo.extensions = convertExtensions(coalesced,
                                        record->extensions_count,
                                        record->extensions);

    chlo.originalEncoding = std::move(original);

    return Param(std::move(chlo));
}

Param convertServerHello(ServerHelloRecord *record, Buf coalesced, Buf original) {
    ServerHello shlo = ServerHello();

    std::copy(std::begin(record->random),
              std::end(record->random),
              std::begin(shlo.random));

    shlo.legacy_session_id_echo = folly::IOBuf::copyBuffer(record->legacy_session_id,
                                                           record->legacy_session_id_length);

    shlo.cipher_suite = CipherSuite(record->cipher_suite);

    shlo.extensions = convertExtensions(coalesced,
                                        record->extensions_count,
                                        record->extensions);

    if (shlo.random == HelloRetryRequest::HrrRandom) {
      HelloRetryRequest hrr;
      hrr.legacy_version = shlo.legacy_version;
      hrr.legacy_session_id_echo = std::move(shlo.legacy_session_id_echo);
      hrr.cipher_suite = shlo.cipher_suite;
      hrr.legacy_compression_method = shlo.legacy_compression_method;
      hrr.extensions = std::move(shlo.extensions);
      hrr.originalEncoding = std::move(original);

      return Param(std::move(hrr));
    }

    shlo.originalEncoding = std::move(original);

    return Param(std::move(shlo));
}

Param convertNewSessionTicket(NewSessionTicketRecord *record, Buf coalesced, Buf original) {
    NewSessionTicket nst = NewSessionTicket();
    nst.ticket_lifetime = record->ticket_lifetime;
    nst.ticket_age_add = record->ticket_age_add;
    nst.ticket_nonce = cloneIntoBuf(coalesced,
                                    record->ticket_nonce_offset,
                                    record->ticket_nonce_length);
    nst.ticket = cloneIntoBuf(coalesced,
                              record->ticket_offset,
                              record->ticket_length);
    nst.extensions = convertExtensions(coalesced,
                                       record->extensions_count,
                                       record->extensions);
    nst.originalEncoding = std::move(original);

    return Param(std::move(nst));
}

Param convertEndOfEarlyData(Buf original) {
    EndOfEarlyData eoed = EndOfEarlyData();
    eoed.originalEncoding = std::move(original);

    return Param(std::move(eoed));
}

Param convertEncryptedExtensions(EncryptedExtensionsRecord *record, Buf coalesced, Buf original) {
    EncryptedExtensions ee = EncryptedExtensions();
    ee.extensions = convertExtensions(coalesced,
                                      record->extensions_count,
                                      record->extensions);
    ee.originalEncoding = std::move(original);
    return Param(std::move(ee));
}

std::vector<CertificateEntry> convertCertificateEntries(Buf const& buf,
                                                        uint8_t certificates_count,
                                                        CertificateEntryRecord certificateEntries[]) {
  std::vector<CertificateEntry> result;

  for (int i = 0; i < certificates_count; i++) {
    result.push_back(
      CertificateEntry{
        cloneIntoBuf(buf, certificateEntries[i].offset, certificateEntries[i].length),
        convertExtensions(buf, certificateEntries[i].extensions_count, certificateEntries[i].extensions)});
  }

  return result;
}

Param convertCertificate(CertificateRecord *record, Buf coalesced, Buf original) {
    CertificateMsg cert = CertificateMsg();
    cert.certificate_request_context = cloneIntoBuf(coalesced,
                                                    record->certificate_request_context_offset,
                                                    record->certificate_request_context_length);
    cert.certificate_list = convertCertificateEntries(coalesced, record->certificates_count, record->certificates);
    cert.originalEncoding = std::move(original);

    return Param(std::move(cert));
}

Param convertCertificateRequest(CertificateRequestRecord *record, Buf coalesced, Buf original) {
    CertificateRequest certRequest = CertificateRequest();
    certRequest.certificate_request_context = cloneIntoBuf(coalesced,
                                                           record->certificate_request_context_offset,
                                                           record->certificate_request_context_length);
    certRequest.extensions = convertExtensions(coalesced, record->extensions_count, record->extensions);
    certRequest.originalEncoding = std::move(original);

    return Param(std::move(certRequest));
}

Param convertCertificateVerify(CertificateVerifyRecord *record, Buf coalesced, Buf original) {
    CertificateVerify certVerify = CertificateVerify();
    certVerify.algorithm = SignatureScheme(record->signature_scheme);
    certVerify.signature = cloneIntoBuf(coalesced,
                                        record->signature_offset,
                                        record->signature_length);
    certVerify.originalEncoding = std::move(original);

    return Param(std::move(certVerify));
}

Param convertFinished(FinishedRecord *record, Buf coalesced, Buf original) {
    Finished fin = Finished();
    fin.verify_data = cloneIntoBuf(coalesced,
                                   record->verify_data_offset,
                                   record->verify_data_length);
    fin.originalEncoding = std::move(original);

    return Param(std::move(fin));
}

Param convertKeyUpdate(KeyUpdateRecord *record, Buf coalesced, Buf original) {
    KeyUpdate update = KeyUpdate();
    update.request_update = KeyUpdateRequest(record->request_update);
    update.originalEncoding = std::move(original);

    return Param(std::move(update));
}

folly::Optional<Param> ReadRecordLayer::decodeHandshakeMessage(
    folly::IOBufQueue& buf) {
  folly::io::Cursor cursor(buf.front());

  if (!cursor.canAdvance(kHandshakeHeaderSize)) {
    return folly::none;
  }

  cursor.readBE<HandshakeTypeType>();
  auto length = detail::readBits24(cursor);

  if (length > kMaxHandshakeSize) {
    throw std::runtime_error("handshake record too big");
  }
  if (buf.chainLength() < (cursor - buf.front()) + length) {
    return folly::none;
  }

  Buf handshakeMsg;
  cursor.clone(handshakeMsg, length);
  auto original = buf.split(kHandshakeHeaderSize + length);

  Buf coalesced = original->cloneCoalesced();

  std::unique_ptr<HandshakeRecord> handshakeRecord(new HandshakeRecord());
  HandshakeRecord *record = handshakeRecord.get();
  parseHandshakeMessage(coalesced->data(), coalesced->length(), &record);

  if (record->tag == 0) {
    throw std::runtime_error("invalid handshake message");
  }

  HandshakeType handshakeType = static_cast<HandshakeType>(record->tag);

  switch (handshakeType) {
    case HandshakeType::client_hello:
      return convertClientHello(&(record->content.client_hello),
                                std::move(coalesced),
                                std::move(original));
    case HandshakeType::server_hello:
      return convertServerHello(&(record->content.server_hello),
                                std::move(coalesced),
                                std::move(original));
    case HandshakeType::end_of_early_data:
      return convertEndOfEarlyData(std::move(original));
    case HandshakeType::new_session_ticket:
      return convertNewSessionTicket(&(record->content.new_session_ticket),
                                     std::move(coalesced),
                                     std::move(original));
    case HandshakeType::encrypted_extensions:
      return convertEncryptedExtensions(&(record->content.encrypted_extensions),
                                        std::move(coalesced),
                                        std::move(original));
    case HandshakeType::certificate:
      return convertCertificate(&(record->content.certificate),
                                std::move(coalesced),
                                std::move(original));
    case HandshakeType::compressed_certificate:
      // TODO: draft-ietf-tls-certificate-compression not supported in GreenTLS
      return parse<CompressedCertificate>(std::move(handshakeMsg), std::move(original));
    case HandshakeType::certificate_request:
      return convertCertificateRequest(&(record->content.certificate_request),
                                       std::move(coalesced),
                                       std::move(original));
    case HandshakeType::certificate_verify:
      return convertCertificateVerify(&(record->content.certificate_verify),
                                      std::move(coalesced),
                                      std::move(original));
    case HandshakeType::finished:
      return convertFinished(&(record->content.finished),
                             std::move(coalesced),
                             std::move(original));
    case HandshakeType::key_update:
      return convertKeyUpdate(&(record->content.key_update),
                              std::move(coalesced),
                              std::move(original));
    default:
      throw std::runtime_error("unknown handshake type");
  };
}

bool ReadRecordLayer::hasUnparsedHandshakeData() const {
  return !unparsedHandshakeData_.empty();
}
} // namespace fizz
