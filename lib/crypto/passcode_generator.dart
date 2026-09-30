import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;

import '../models/hash_algorithm.dart';
import 'sm3.dart';
import 'sm4.dart';

/// 核心 HOTP/TOTP 生成器，与安卓版 PasscodeGenerator.java 完全对应。
///
/// 支持算法：
/// - SHA1/SHA256/SHA512/SHA224/SHA384/MD5：RFC 4226 标准动态截取
/// - SM3：HMAC-SM3，依据 GMT 0021-2023 规范截位
/// - CBCSM4：TrCBC-SM4，依据 GMT 0021-2023 规范
class PasscodeGenerator {
  static const int defaultDigits = 6;
  static const int defaultTimeStepSeconds = 30;

  static const List<int> _pow10 = [
    1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000,
  ];

  PasscodeGenerator._();

  /// 64 位计数器 → 8 字节大端序
  static List<int> longToBytes(int value) {
    final bytes = Uint8List(8);
    final bd = ByteData.view(bytes.buffer);
    bd.setUint64(0, value);
    return bytes;
  }

  /// 生成 OTP 口令
  static String generate(int counter, List<int> secret, HashAlgorithm algorithm, int digits) {
    if (digits < 1 || digits > 9) {
      throw ArgumentError('digits must be 1..9, got $digits');
    }
    if (secret.isEmpty) {
      throw ArgumentError('secret is empty');
    }

    // ======= CBC-SM4 特殊路径 =======
    if (algorithm.isCbcSm4) {
      final challenge = longToBytes(counter);
      final inputBytes = _padTo128bit(challenge);
      final mac = Sm4.cbcMac(inputBytes, secret);
      final od = _cbcSm4Truncation(mac);
      final unsignedOd = od & 0xFFFFFFFF;
      final code = unsignedOd % _pow10[digits];
      return _padWithZeros(code, digits);
    }

    // ======= HMAC 路径 =======
    final challenge = longToBytes(counter);
    // SM3 依据 GMT 0021-2023：输入序列不足 128bit 在末端填 0 至 128bit
    final inputBytes = algorithm.isSm3 ? _padTo128bit(challenge) : challenge;

    List<int> hash;
    if (algorithm.isSm3) {
      hash = Sm3.hmac(secret, inputBytes);
    } else {
      hash = _computeHmac(secret, inputBytes, algorithm);
    }

    // 截位运算
    if (algorithm.isSm3) {
      final od = _sm3DynamicTruncation(hash);
      final unsignedOd = od & 0xFFFFFFFF;
      final code = unsignedOd % _pow10[digits];
      return _padWithZeros(code, digits);
    } else {
      return _truncate(hash, digits);
    }
  }

  /// 使用 crypto 包计算 HMAC（SHA1/SHA256/SHA512/SHA224/SHA384/MD5）
  static List<int> _computeHmac(List<int> key, List<int> data, HashAlgorithm algo) {
    crypto.Hash hash;
    switch (algo) {
      case HashAlgorithm.sha1:
        hash = crypto.sha1;
        break;
      case HashAlgorithm.sha256:
        hash = crypto.sha256;
        break;
      case HashAlgorithm.sha512:
        hash = crypto.sha512;
        break;
      case HashAlgorithm.sha224:
        hash = crypto.sha224;
        break;
      case HashAlgorithm.sha384:
        hash = crypto.sha384;
        break;
      case HashAlgorithm.md5:
        hash = crypto.md5;
        break;
      default:
        throw ArgumentError('Unsupported HMAC algorithm: ${algo.canonical}');
    }
    final hmac = crypto.Hmac(hash, key);
    return hmac.convert(data).bytes;
  }

  /// 输入序列填充至 128bit（16 字节）— 依据 GMT 0021-2023
  static List<int> _padTo128bit(List<int> input) {
    if (input.length >= 16) return input;
    final padded = List<int>.filled(16, 0);
    padded.setAll(0, input);
    return padded;
  }

  /// SM3 截位运算 — 依据 GMT 0021-2023
  /// 将 256bit 输出划分为 8 个 4 字节整数 S1..S8
  /// OD = (S1+...+S8) mod 2^32
  static int _sm3DynamicTruncation(List<int> hash) {
    if (hash.length < 32) {
      throw ArgumentError('SM3 HMAC output must be 32 bytes, got ${hash.length}');
    }
    int sum = 0;
    const int mod = 0x100000000; // 2^32
    for (int i = 0; i < 8; i++) {
      final s = ((hash[i * 4] & 0xFF) << 24) |
          ((hash[i * 4 + 1] & 0xFF) << 16) |
          ((hash[i * 4 + 2] & 0xFF) << 8) |
          (hash[i * 4 + 3] & 0xFF);
      sum = (sum + (s & 0xFFFFFFFF)) % mod;
    }
    return sum;
  }

  /// CBC-SM4 截位运算 — 依据 GMT 0021-2023
  /// 将 128bit MAC 输出划分为 4 个 4 字节整数 S1..S4
  /// OD = (S1+S2+S3+S4) mod 2^32
  static int _cbcSm4Truncation(List<int> mac) {
    if (mac.length != 16) {
      throw ArgumentError('CBC-SM4 MAC must be 16 bytes, got ${mac.length}');
    }
    int sum = 0;
    const int mod = 0x100000000;
    for (int i = 0; i < 4; i++) {
      final s = ((mac[i * 4] & 0xFF) << 24) |
          ((mac[i * 4 + 1] & 0xFF) << 16) |
          ((mac[i * 4 + 2] & 0xFF) << 8) |
          (mac[i * 4 + 3] & 0xFF);
      sum = (sum + (s & 0xFFFFFFFF)) % mod;
    }
    return sum;
  }

  /// RFC 4226 标准动态截取（SHA1/SHA256/SHA512/SHA224/SHA384/MD5）
  static String _truncate(List<int> hash, int digits) {
    if (hash.length < 4) {
      throw ArgumentError('hash too short');
    }
    // MD5 输出 16 字节，使用 0x0C 掩码；其他算法输出 ≥20 字节，使用标准 0x0F
    final offsetMask = hash.length >= 20 ? 0x0F : 0x0C;
    final offset = hash[hash.length - 1] & offsetMask;

    final raw = ((hash[offset] & 0x7F) << 24) |
        ((hash[offset + 1] & 0xFF) << 16) |
        ((hash[offset + 2] & 0xFF) << 8) |
        (hash[offset + 3] & 0xFF);

    final code = raw % _pow10[digits];
    return _padWithZeros(code, digits);
  }

  /// 左侧补零至指定位数
  static String _padWithZeros(int code, int digits) {
    final s = code.toString();
    return s.padLeft(digits, '0');
  }

  /// 便捷方法：计算 TOTP
  static String totp(
    int unixSeconds,
    List<int> secret,
    HashAlgorithm algorithm,
    int digits,
    int timeStepSeconds,
  ) {
    final step = timeStepSeconds <= 0 ? defaultTimeStepSeconds : timeStepSeconds;
    final counter = unixSeconds ~/ step;
    return generate(counter, secret, algorithm, digits);
  }

  /// 便捷方法：计算 HOTP
  static String hotp(int counter, List<int> secret, HashAlgorithm algorithm, int digits) {
    return generate(counter, secret, algorithm, digits);
  }
}
