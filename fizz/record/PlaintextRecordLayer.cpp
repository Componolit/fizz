/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/record/PlaintextRecordLayer.h>

#include <folly/String.h>

#include "greentls.hpp"

namespace fizz {

using ContentTypeType = typename std::underlying_type<ContentType>::type;
using ProtocolVersionType =
    typename std::underlying_type<ProtocolVersion>::type;

static constexpr uint16_t kMaxPlaintextRecordSize = 0x4000; // 16k
static constexpr size_t kPlaintextHeaderSize =
    sizeof(ContentType) + sizeof(ProtocolVersion) + sizeof(uint16_t);

folly::Optional<TLSMessage> PlaintextReadRecordLayer::read(
    folly::IOBufQueue& buf) {
  while (true) {
    folly::io::Cursor cursor(buf.front());

    if (buf.empty() || !cursor.canAdvance(kPlaintextHeaderSize)) {
      return folly::none;
    }

    Buf b;
    cursor.cloneAtMost(b, 65536);
    if (b->isChained()) {
      b->coalesce();
    }

    std::unique_ptr<RecordRecord> recordPtr(new RecordRecord());
    RecordRecord *record = recordPtr.get();
    parseRecordMessage(b->data(), b->length(), &record);

    if (b->length() < kPlaintextHeaderSize + record->length) {
      return folly::none;
    }

    if (skipEncryptedRecords_) {
      if (!record->valid_ciphertext && record->content_type == 0 && record->length == 0) {
        throw FizzException("invalid encrypted record message", AlertDescription::decode_error);
      }

      ContentType type = ContentType(record->content_type);

      if (type == ContentType::application_data) {
        buf.trimStart(kPlaintextHeaderSize + record->length);
        continue;
      } else if (type != ContentType::change_cipher_spec) {
        skipEncryptedRecords_ = false;
      }
    }

    TLSMessage msg;
    msg.type = ContentType(record->content_type);

    switch (msg.type) {
      case ContentType::handshake:
      case ContentType::alert:
        break;
      case ContentType::change_cipher_spec:
        break;
      default:
        throw std::runtime_error(folly::to<std::string>(
            "received plaintext content type ",
            static_cast<ContentTypeType>(msg.type),
            ", header: ",
            folly::hexlify(buf.splitAtMost(10)->coalesce())));
    }

    auto length = record->length;
    if (length > kMaxPlaintextRecordSize) {
      throw std::runtime_error("received too long plaintext record");
    }
    if (length == 0) {
      throw std::runtime_error("received empty plaintext record");
    }

    cursor = folly::io::Cursor(buf.front());
    cursor.skip(kPlaintextHeaderSize);
    cursor.clone(msg.fragment, length);

    buf.trimStart(cursor - buf.front());

    if (msg.type == ContentType::change_cipher_spec) {
      msg.fragment->coalesce();
      if (msg.fragment->length() == 1 && *msg.fragment->data() == 0x01) {
        continue;
      } else {
        throw FizzException(
            "received ccs", AlertDescription::illegal_parameter);
      }
    }

    if (!record->valid_plaintext || record->content_type == 0) {
      throw FizzException("invalid record message", AlertDescription::decode_error);
    }

    return std::move(msg);
  }
}

EncryptionLevel PlaintextReadRecordLayer::getEncryptionLevel() const {
  return EncryptionLevel::Plaintext;
}

TLSContent PlaintextWriteRecordLayer::write(TLSMessage&& msg) const {
  return write(std::move(msg), ProtocolVersion::tls_1_2);
}

TLSContent PlaintextWriteRecordLayer::writeInitialClientHello(
    Buf encodedClientHello) const {
  return write(
      TLSMessage{ContentType::handshake, std::move(encodedClientHello)},
      ProtocolVersion::tls_1_0);
}

TLSContent PlaintextWriteRecordLayer::write(
    TLSMessage msg,
    ProtocolVersion recordVersion) const {
  if (msg.type == ContentType::application_data) {
    throw std::runtime_error("refusing to send plaintext application data");
  }

  auto fragment = std::move(msg.fragment);
  folly::io::Cursor cursor(fragment.get());
  std::unique_ptr<folly::IOBuf> data;
  while (!cursor.isAtEnd()) {
    Buf thisFragment;
    auto len = cursor.cloneAtMost(thisFragment, kMaxPlaintextRecordSize);

    auto header = folly::IOBuf::create(kPlaintextHeaderSize);
    folly::io::Appender appender(header.get(), kPlaintextHeaderSize);
    appender.writeBE(static_cast<ContentTypeType>(msg.type));
    appender.writeBE(static_cast<ProtocolVersionType>(recordVersion));
    appender.writeBE<uint16_t>(len);

    if (!data) {
      data = std::move(header);
    } else {
      data->prependChain(std::move(header));
    }
    data->prependChain(std::move(thisFragment));
  }
  TLSContent content;
  content.data = std::move(data);
  content.contentType = msg.type;
  content.encryptionLevel = EncryptionLevel::Plaintext;
  return content;
}

EncryptionLevel PlaintextWriteRecordLayer::getEncryptionLevel() const {
  return EncryptionLevel::Plaintext;
}
} // namespace fizz
