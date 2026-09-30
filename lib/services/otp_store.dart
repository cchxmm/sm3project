import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../models/otp_entry.dart';
import '../models/otp_type.dart';

/// OTP 账号持久化存储，使用 SharedPreferences + JSON。
/// 与安卓版 OtpStore.java 对应。
class OtpStore extends ChangeNotifier {
  static const String _prefsName = 'otp_store';
  static const String _keyEntries = 'entries_json';

  static OtpStore? _instance;
  SharedPreferences? _prefs;

  OtpStore._();

  static OtpStore get instance {
    _instance ??= OtpStore._();
    return _instance!;
  }

  Future<void> init() async {
    _prefs ??= await SharedPreferences.getInstance();
  }

  List<OtpEntry> getAll() {
    final json = _prefs?.getString(_keyEntries);
    if (json == null) return [];
    try {
      final List<dynamic> raw = jsonDecode(json) as List<dynamic>;
      return raw
          .map((e) => OtpEntry.fromJson(e as Map<String, dynamic>))
          .toList();
    } catch (_) {
      return [];
    }
  }

  Future<void> save(OtpEntry entry) async {
    final all = getAll();
    var replaced = false;
    for (int i = 0; i < all.length; i++) {
      if (all[i].id == entry.id) {
        all[i] = entry;
        replaced = true;
        break;
      }
    }
    if (!replaced) all.add(entry);
    await _persist(all);
  }

  Future<void> delete(String id) async {
    final all = getAll()..removeWhere((e) => e.id == id);
    await _persist(all);
  }

  Future<void> replaceAll(List<OtpEntry> entries) async {
    await _persist(entries);
  }

  /// HOTP：展示/复制口令后计数器 +1
  Future<void> incrementHotpCounter(String id) async {
    final all = getAll();
    for (final e in all) {
      if (e.id == id && e.type == OtpType.hotp && e.counter != null) {
        e.counter = e.counter! + 1;
      }
    }
    await _persist(all);
  }

  Future<void> _persist(List<OtpEntry> entries) async {
    final json = jsonEncode(entries.map((e) => e.toJson()).toList());
    await _prefs?.setString(_keyEntries, json);
    notifyListeners();
  }
}
