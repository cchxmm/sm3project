/// OTP 类型：TOTP（基于时间）或 HOTP（基于计数器）
enum OtpType {
  totp(canonical: 'totp'),
  hotp(canonical: 'hotp');

  final String canonical;

  const OtpType({required this.canonical});

  static OtpType fromString(String? value) {
    if (value == null) return OtpType.totp;
    for (final t in OtpType.values) {
      if (t.canonical.toLowerCase() == value.toLowerCase()) {
        return t;
      }
    }
    return OtpType.totp;
  }
}
