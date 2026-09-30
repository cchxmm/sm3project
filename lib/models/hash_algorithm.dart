/// HMAC 算法枚举，与安卓版 HashAlgorithm 完全对应。
///
/// 支持八种算法：
/// - SHA1   — HmacSHA1, RFC 4226 默认
/// - SHA256 — HmacSHA256
/// - SHA512 — HmacSHA512
/// - SHA224 — HmacSHA224
/// - SHA384 — HmacSHA384
/// - MD5    — HmacMD5
/// - SM3    — HmacSM3, 依据 GMT 0021-2023 规范
/// - CBCSM4 — TrCBC-SM4, 依据 GMT 0021-2023 规范
enum HashAlgorithm {
  sha1(macName: 'HmacSHA1', canonical: 'SHA1'),
  sha256(macName: 'HmacSHA256', canonical: 'SHA256'),
  sha512(macName: 'HmacSHA512', canonical: 'SHA512'),
  sha224(macName: 'HmacSHA224', canonical: 'SHA224'),
  sha384(macName: 'HmacSHA384', canonical: 'SHA384'),
  md5(macName: 'HmacMD5', canonical: 'MD5'),
  sm3(macName: 'HmacSM3', canonical: 'SM3'),
  cbcSm4(macName: 'CBCSM4', canonical: 'SM4');

  final String macName;
  final String canonical;

  const HashAlgorithm({required this.macName, required this.canonical});

  /// 是否为 SM3 算法 — 使用 GMT 0021-2023 规范的截位方式
  bool get isSm3 => this == HashAlgorithm.sm3;

  /// 是否为 CBC-SM4 算法 — 非 HMAC，基于 CBC-MAC
  bool get isCbcSm4 => this == HashAlgorithm.cbcSm4;

  /// 通过 canonical 名称或 mac 名称查找，大小写不敏感
  static HashAlgorithm fromString(String? value) {
    if (value == null) return HashAlgorithm.sha1;
    final v = value.trim();
    for (final a in HashAlgorithm.values) {
      if (a.canonical.toLowerCase() == v.toLowerCase() ||
          a.macName.toLowerCase() == v.toLowerCase()) {
        return a;
      }
    }
    return HashAlgorithm.sha1;
  }

  /// UI 下拉框索引 → 算法（与安卓版 otp_algorithms 数组顺序一致）
  static HashAlgorithm fromIndex(int index) {
    switch (index) {
      case 1:
        return HashAlgorithm.sha256;
      case 2:
        return HashAlgorithm.sha512;
      case 3:
        return HashAlgorithm.sha224;
      case 4:
        return HashAlgorithm.sha384;
      case 5:
        return HashAlgorithm.md5;
      case 6:
        return HashAlgorithm.sm3;
      case 7:
        return HashAlgorithm.cbcSm4;
      default:
        return HashAlgorithm.sha1;
    }
  }
}
