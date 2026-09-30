import 'dart:convert';
import '../models/hash_algorithm.dart';
import '../models/otp_entry.dart';
import '../models/otp_type.dart';
import '../crypto/base32.dart';
import 'otp_uri.dart';

/// 解析 Google Authenticator "导出账号"二维码使用的迁移 URI。
/// 与安卓版 OtpMigration.java 对应。
class OtpMigration {
  OtpMigration._();

  static OtpUriResult parse(String uri) {
    try {
      final data = _extractDataParam(uri);
      if (data == null || data.isEmpty) {
        return const OtpUriResult(error: '迁移码中缺少 data 参数', otpLike: true);
      }

      final payload = _decodeUrlSafeBase64(data);
      if (payload.isEmpty) {
        return const OtpUriResult(error: '迁移码 Base64 解码失败', otpLike: true);
      }

      final entries = <OtpEntry>[];
      _parsePayload(payload, entries);

      if (entries.isEmpty) {
        return const OtpUriResult(error: '迁移码中没有可导入的账号', otpLike: true);
      }
      return OtpUriResult(entries: entries, otpLike: true);
    } catch (e) {
      return OtpUriResult(error: '迁移码解析失败：$e', otpLike: true);
    }
  }

  static String? _extractDataParam(String uri) {
    final qIdx = uri.indexOf('?');
    final query = qIdx >= 0 ? uri.substring(qIdx + 1) : '';
    final q = query.replaceAll('&amp;', '&');
    for (final pair in q.split('&')) {
      if (pair.startsWith('data=')) {
        return pair.substring(5);
      }
    }
    return null;
  }

  static List<int> _decodeUrlSafeBase64(String raw) {
    var s = raw.trim().replaceAll('-', '+').replaceAll('_', '/');
    final mod = s.length % 4;
    if (mod == 2) {
      s += '==';
    } else if (mod == 3) {
      s += '=';
    }
    return base64Decode(s);
  }

  // ------------------------------------------------------------------
  // protobuf wire 解析
  // ------------------------------------------------------------------

  static void _parsePayload(List<int> data, List<OtpEntry> out) {
    final r = _ProtobufReader(data);
    while (r.hasMore()) {
      final tag = r.readVarint();
      final field = tag >> 3;
      final wireType = tag & 0x07;
      if (field == 1 && wireType == 2) {
        final sub = r.readBytes();
        final e = _parseOtpParameters(sub);
        if (e != null) out.add(e);
      } else {
        r.skipField(wireType);
      }
    }
  }

  static OtpEntry? _parseOtpParameters(List<int> data) {
    final r = _ProtobufReader(data);
    List<int>? secret;
    String? accountName;
    String? issuer;
    var algorithmValue = 0;
    var digitsValue = 0;
    var typeValue = 0;
    var counter = 0;

    while (r.hasMore()) {
      final tag = r.readVarint();
      final field = tag >> 3;
      final wireType = tag & 0x07;
      switch (field) {
        case 1: // bytes secret
          if (wireType == 2) secret = r.readBytes();
          break;
        case 2: // string account_name
          accountName = wireType == 2 ? r.readUtf8() : null;
          break;
        case 3: // string issuer
          issuer = wireType == 2 ? r.readUtf8() : null;
          break;
        case 4: // enum algorithm
          algorithmValue = wireType == 0 ? r.readVarint() : 0;
          break;
        case 5: // enum digits
          digitsValue = wireType == 0 ? r.readVarint() : 0;
          break;
        case 6: // enum type
          typeValue = wireType == 0 ? r.readVarint() : 0;
          break;
        case 7: // uint64 counter
          counter = wireType == 0 ? r.readVarint() : 0;
          break;
        default:
          r.skipField(wireType);
      }
    }

    if (secret == null || secret.isEmpty) return null;

    final secretBase32 = Base32.encode(secret);

    HashAlgorithm algo;
    switch (algorithmValue) {
      case 2:
        algo = HashAlgorithm.sha256;
        break;
      case 3:
        algo = HashAlgorithm.sha512;
        break;
      default:
        algo = HashAlgorithm.sha1;
    }

    int digits;
    switch (digitsValue) {
      case 2:
        digits = 7;
        break;
      case 3:
        digits = 8;
        break;
      default:
        digits = 6;
    }

    final type = typeValue == 1 ? OtpType.hotp : OtpType.totp;
    final counterBoxed = type == OtpType.hotp ? counter : null;

    var name = accountName?.trim() ?? '';
    var issuerTrimmed = issuer?.trim();
    if (issuerTrimmed != null && issuerTrimmed.isEmpty) issuerTrimmed = null;
    if (name.isEmpty) {
      name = issuerTrimmed ?? '未命名账号';
    }

    return OtpEntry(
      name: name,
      secret: secretBase32,
      type: type,
      counter: counterBoxed,
      algorithm: algo,
      digits: digits,
      issuer: issuerTrimmed,
    );
  }
}

/// 极简 protobuf reader，仅支持 varint 与 length-delimited
class _ProtobufReader {
  final List<int> _data;
  int _pos = 0;

  _ProtobufReader(this._data);

  bool hasMore() => _pos < _data.length;

  int readVarint() {
    var result = 0;
    var shift = 0;
    while (true) {
      if (_pos >= _data.length) {
        throw StateError('varint 越界');
      }
      final b = _data[_pos++];
      result |= (b & 0x7F) << shift;
      if ((b & 0x80) == 0) break;
      shift += 7;
      if (shift > 63) {
        throw StateError('varint 过长');
      }
    }
    return result;
  }

  List<int> readBytes() {
    final length = readVarint();
    if (length < 0 || _pos + length > _data.length) {
      throw StateError('字节段越界');
    }
    final out = _data.sublist(_pos, _pos + length);
    _pos += length;
    return out;
  }

  String readUtf8() => utf8.decode(readBytes());

  void skipField(int wireType) {
    switch (wireType) {
      case 0: // varint
        readVarint();
        break;
      case 1: // 64-bit
        _advance(8);
        break;
      case 2: // length-delimited
        final length = readVarint();
        _advance(length);
        break;
      case 5: // 32-bit
        _advance(4);
        break;
      default:
        throw StateError('不支持的 wire type: $wireType');
    }
  }

  void _advance(int n) {
    if (_pos + n > _data.length) {
      throw StateError('跳过字段越界');
    }
    _pos += n;
  }
}
