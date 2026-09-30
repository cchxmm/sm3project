import '../models/hash_algorithm.dart';
import '../models/otp_entry.dart';
import '../models/otp_type.dart';
import '../crypto/base32.dart';
import 'otp_migration.dart';

/// 解析结果
class OtpUriResult {
  final List<OtpEntry> entries;
  final String? error;
  final bool otpLike;

  const OtpUriResult({this.entries = const [], this.error, this.otpLike = false});

  bool get isSuccess => error == null && entries.isNotEmpty;
}

/// 解析二维码 / 外部链接中的 OTP URI。
/// 与安卓版 OtpUri.java 对应。
class OtpUri {
  OtpUri._();

  /// 解析任意扫码文本，自动识别标准 otpauth 与 otpauth-migration
  static OtpUriResult parseAny(String? raw) {
    if (raw == null) {
      return const OtpUriResult(error: '二维码内容为空', otpLike: false);
    }
    final s = _sanitize(raw);
    if (s.isEmpty) {
      return const OtpUriResult(error: '二维码内容为空', otpLike: false);
    }

    final lower = s.toLowerCase();
    if (lower.startsWith('otpauth-migration://')) {
      return OtpMigration.parse(s);
    }
    if (lower.startsWith('otpauth://')) {
      return _parseStandard(s);
    }
    return const OtpUriResult(otpLike: false);
  }

  // ------------------------------------------------------------------
  // 标准 otpauth:// 解析
  // ------------------------------------------------------------------

  static OtpUriResult _parseStandard(String s) {
    try {
      final schemeEnd = s.indexOf('://');
      final remainder = s.substring(schemeEnd + 3);

      final queryStart = _locateQueryStart(remainder);
      final String authorityPath;
      final String queryString;
      if (queryStart >= 0) {
        authorityPath = remainder.substring(0, queryStart);
        queryString = remainder.substring(queryStart + 1);
      } else {
        authorityPath = remainder;
        queryString = '';
      }

      final slash = authorityPath.indexOf('/');
      String host;
      String label;
      if (slash >= 0) {
        host = authorityPath.substring(0, slash);
        label = Uri.decodeComponent(authorityPath.substring(slash + 1));
      } else {
        host = authorityPath;
        label = '';
      }

      OtpType type;
      switch (host.trim().toLowerCase()) {
        case 'hotp':
          type = OtpType.hotp;
          break;
        case 'totp':
        case '':
          type = OtpType.totp;
          break;
        default:
          type = OtpType.totp;
      }

      final params = _parseQuery(queryString);

      var secretParam = params['secret'];
      secretParam ??= params['key'];
      if (secretParam == null || secretParam.isEmpty) {
        return const OtpUriResult(error: '二维码中缺少密钥（secret）参数', otpLike: true);
      }
      final secret = OtpEntry.normalizeSecret(secretParam);
      if (secret.isEmpty) {
        return const OtpUriResult(error: '二维码中的密钥为空', otpLike: true);
      }
      try {
        final keyBytes = Base32.decode(secret);
        if (keyBytes.isEmpty) {
          return const OtpUriResult(error: '二维码中的密钥解码后为空', otpLike: true);
        }
      } catch (e) {
        return OtpUriResult(error: '密钥不是有效的 Base32 编码（$e）', otpLike: true);
      }

      String? issuer = _cleanIssuer(params['issuer']);
      var name = '';
      if (label.isNotEmpty) {
        final colon = _indexOfLabelSeparator(label);
        if (colon >= 0) {
          final labelIssuer = _cleanIssuer(label.substring(0, colon));
          name = label.substring(colon + 1).trim();
          if (issuer == null && labelIssuer != null) issuer = labelIssuer;
        } else {
          name = label.trim();
        }
      }
      if (name.isEmpty) {
        name = issuer ?? '未命名账号';
      }

      final algo = _parseAlgorithm(params['algorithm']);

      var digits = 6;
      final digitsQ = params['digits'];
      if (digitsQ != null) {
        final d = int.tryParse(digitsQ.trim());
        if (d == 6 || d == 7 || d == 8) digits = d;
      }

      var period = 30;
      final periodQ = params['period'];
      if (periodQ != null) {
        final p = int.tryParse(periodQ.trim());
        if (p != null && p >= 1 && p <= 600) period = p;
      }

      int? counter;
      final counterQ = params['counter'];
      if (counterQ != null) {
        counter = int.tryParse(counterQ.trim());
      }
      if (type == OtpType.hotp && counter == null) counter = 0;
      if (counter != null && counter < 0) counter = 0;

      final entry = OtpEntry(
        name: name,
        secret: secret,
        type: type,
        counter: counter,
        algorithm: algo,
        digits: digits,
        timeStepSeconds: period,
        issuer: issuer,
      );
      return OtpUriResult(entries: [entry], otpLike: true);
    } catch (e) {
      return OtpUriResult(error: 'URI 格式错误：$e', otpLike: true);
    }
  }

  static int _locateQueryStart(String remainder) {
    var paramIdx = _indexOfParamStart(remainder, 'secret');
    if (paramIdx < 0) paramIdx = _indexOfParamStart(remainder, 'key');
    if (paramIdx > 0) {
      for (int i = paramIdx - 1; i >= 0; i--) {
        final c = remainder[i];
        if (c == '?' || c == '&') return i;
      }
    }
    return remainder.indexOf('?');
  }

  static int _indexOfParamStart(String text, String name) {
    final lower = text.toLowerCase();
    final needle = '${name.toLowerCase()}=';
    var from = 0;
    while (from <= lower.length - needle.length) {
      final idx = lower.indexOf(needle, from);
      if (idx < 0) return -1;
      if (idx == 0) return idx;
      final prev = text[idx - 1];
      if (prev == '?' || prev == '&') return idx;
      from = idx + 1;
    }
    return -1;
  }

  static int _indexOfLabelSeparator(String label) {
    final half = label.indexOf(':');
    final full = label.indexOf('：');
    if (half < 0) return full;
    if (full < 0) return half;
    return half < full ? half : full;
  }

  static String? _cleanIssuer(String? raw) {
    if (raw == null) return null;
    final t = raw.trim();
    if (t.isEmpty) return null;
    if (t.contains('?')) return null;
    return t;
  }

  static Map<String, String> _parseQuery(String queryString) {
    final map = <String, String>{};
    if (queryString.isEmpty) return map;
    final q = queryString.replaceAll('&amp;', '&');
    for (final pair in q.split('&')) {
      if (pair.isEmpty) continue;
      final eq = pair.indexOf('=');
      String key;
      String value;
      if (eq >= 0) {
        key = pair.substring(0, eq);
        value = pair.substring(eq + 1);
      } else {
        key = pair;
        value = '';
      }
      map[Uri.decodeComponent(key).trim().toLowerCase()] =
          Uri.decodeComponent(value);
    }
    return map;
  }

  static HashAlgorithm _parseAlgorithm(String? raw) {
    if (raw == null) return HashAlgorithm.sha1;
    var a = raw.trim().toUpperCase();
    if (a.startsWith('HMAC-')) a = a.substring(5);
    if (a.startsWith('HMAC')) a = a.substring(4);
    switch (a) {
      case 'SHA256':
      case 'SHA-256':
      case '256':
        return HashAlgorithm.sha256;
      case 'SHA512':
      case 'SHA-512':
      case '512':
        return HashAlgorithm.sha512;
      case 'SHA224':
      case 'SHA-224':
      case '224':
        return HashAlgorithm.sha224;
      case 'SHA384':
      case 'SHA-384':
      case '384':
        return HashAlgorithm.sha384;
      case 'MD5':
      case 'MD-5':
        return HashAlgorithm.md5;
      case 'SM3':
      case 'SM-3':
        return HashAlgorithm.sm3;
      case 'SM4':
      case 'SM-4':
      case 'CBC-SM4':
      case 'CBCSM4':
        return HashAlgorithm.cbcSm4;
      case 'SHA1':
      case 'SHA-1':
      case '1':
        return HashAlgorithm.sha1;
      default:
        return HashAlgorithm.sha1;
    }
  }

  static String _sanitize(String raw) {
    return raw
        .replaceAll('\uFEFF', '')
        .replaceAll(RegExp(r'[\u200B-\u200D\u2060]'), '')
        .replaceAll(RegExp(r'[\x00-\x1F\x7F]'), '')
        .trim();
  }
}
