import 'package:uuid/uuid.dart';

import 'hash_algorithm.dart';
import 'otp_type.dart';
import '../crypto/base32.dart';

/// 一个 OTP 账号的内存表示，与安卓版 OtpEntry 完全对应。
class OtpEntry {
  final String id;
  String? issuer;
  String name;
  final String secret; // Base32（无空格/无填充）
  final OtpType type;
  int? counter; // HOTP 专用，TOTP 为 null
  HashAlgorithm algorithm;
  int digits;
  int timeStepSeconds;
  final int createdAt; // 毫秒时间戳

  OtpEntry({
    String? id,
    this.issuer,
    required this.name,
    required this.secret,
    required this.type,
    this.counter,
    HashAlgorithm? algorithm,
    int? digits,
    int? timeStepSeconds,
    int? createdAt,
  })  : id = id ?? const Uuid().v4(),
        algorithm = algorithm ?? HashAlgorithm.sha1,
        digits = (digits == null || digits <= 0) ? 6 : digits,
        timeStepSeconds =
            (timeStepSeconds == null || timeStepSeconds <= 0) ? 30 : timeStepSeconds,
        createdAt = createdAt ?? DateTime.now().millisecondsSinceEpoch;

  /// 工厂方法：创建新录入的 TOTP/HOTP 账号
  factory OtpEntry.create({
    required String issuer,
    required String name,
    required String secret,
    required OtpType type,
    required int counter,
    required HashAlgorithm algorithm,
    required int digits,
  }) {
    return OtpEntry(
      issuer: issuer.isEmpty ? null : issuer,
      name: name,
      secret: normalizeSecret(secret),
      type: type,
      counter: type == OtpType.hotp ? counter : null,
      algorithm: algorithm,
      digits: digits,
    );
  }

  /// 去除空格/短横线/下划线并转大写，与 Base32.decode 兼容
  static String normalizeSecret(String raw) {
    return raw
        .replaceAll(RegExp(r'\s+'), '')
        .replaceAll('-', '')
        .replaceAll('_', '')
        .toUpperCase()
        .replaceAll('=', '');
  }

  /// 解码 Base32 密钥为原始字节
  List<int> decodeSecret() => Base32.decode(secret);

  /// "Issuer: Name" 或仅 "Name"
  String displayName() {
    if (issuer == null || issuer!.isEmpty) {
      return name.isEmpty ? '(未命名)' : name;
    }
    return name.isEmpty ? issuer! : '$issuer: $name';
  }

  /// 两字母头像标签
  String initials() {
    final src = (issuer == null || issuer!.isEmpty) ? name : issuer!;
    if (src.isEmpty) return '?';
    final trimmed = src.trim();
    final sp = trimmed.indexOf(' ');
    if (sp > 0 && sp + 1 < trimmed.length) {
      return ('${trimmed[0]}${trimmed[sp + 1]}').toUpperCase();
    }
    return trimmed.substring(0, trimmed.length < 2 ? trimmed.length : 2).toUpperCase();
  }

  /// 序列化为 JSON（用于持久化存储）
  Map<String, dynamic> toJson() => {
        'id': id,
        'issuer': issuer,
        'name': name,
        'secret': secret,
        'type': type.canonical,
        'counter': counter,
        'algorithm': algorithm.canonical,
        'digits': digits,
        'timeStep': timeStepSeconds,
        'createdAt': createdAt,
      };

  /// 从 JSON 反序列化
  factory OtpEntry.fromJson(Map<String, dynamic> json) => OtpEntry(
        id: json['id'] as String?,
        issuer: json['issuer'] as String?,
        name: json['name'] as String? ?? '',
        secret: json['secret'] as String? ?? '',
        type: OtpType.fromString(json['type'] as String?),
        counter: json['counter'] as int?,
        algorithm: HashAlgorithm.fromString(json['algorithm'] as String?),
        digits: json['digits'] as int? ?? 6,
        timeStepSeconds: json['timeStep'] as int? ?? 30,
        createdAt: json['createdAt'] as int?,
      );

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is OtpEntry && id == other.id;

  @override
  int get hashCode => id.hashCode;
}
