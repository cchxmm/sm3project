/// Base32 (RFC 4648) 编解码器，与安卓版 Base32.java 完全一致。
///
/// 使用字母表 "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"，与 Google Authenticator 一致。
class Base32 {
  static const String _alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  Base32._();

  /// 解码 Base32 字符串为原始字节
  static List<int> decode(String input) {
    // 去除空白和填充，转大写
    final s = input
        .replaceAll(RegExp(r'\s+'), '')
        .replaceAll('=', '')
        .toUpperCase();
    if (s.isEmpty) return <int>[];

    // 校验字符
    for (int i = 0; i < s.length; i++) {
      if (_alphabet.indexOf(s[i]) < 0) {
        throw ArgumentError('Invalid Base32 character at position $i: ${s[i]}');
      }
    }

    final byteLength = s.length * 5 ~/ 8;
    final result = List<int>.filled(byteLength, 0);
    int buffer = 0;
    int bits = 0;
    int outIdx = 0;

    for (int i = 0; i < s.length; i++) {
      final value = _alphabet.indexOf(s[i]);
      buffer = (buffer << 5) | value;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        result[outIdx++] = (buffer >> bits) & 0xFF;
        if (outIdx >= byteLength) break;
      }
    }
    return result;
  }

  /// 编码原始字节为 Base32 字符串
  static String encode(List<int> data) {
    if (data.isEmpty) return '';
    final sb = StringBuffer();
    int buffer = 0;
    int bitsLeft = 0;

    for (final b in data) {
      buffer = (buffer << 8) | (b & 0xFF);
      bitsLeft += 8;
      while (bitsLeft >= 5) {
        final index = (buffer >> (bitsLeft - 5)) & 0x1F;
        sb.write(_alphabet[index]);
        bitsLeft -= 5;
      }
    }
    if (bitsLeft > 0) {
      final index = (buffer << (5 - bitsLeft)) & 0x1F;
      sb.write(_alphabet[index]);
    }
    return sb.toString();
  }
}
