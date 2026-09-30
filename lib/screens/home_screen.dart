import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../models/otp_entry.dart';
import '../models/otp_type.dart';
import '../services/otp_store.dart';
import '../crypto/passcode_generator.dart';
import '../widgets/otp_tile.dart';
import '../widgets/add_account_sheet.dart';
import 'scan_screen.dart';
import 'enter_key_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final List<OtpEntry> _entries = [];
  bool _ticking = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      Provider.of<OtpStore>(context, listen: false).addListener(_onStoreChanged);
      _loadEntries();
    });
    _startTicking();
  }

  @override
  void dispose() {
    _ticking = false;
    super.dispose();
  }

  void _onStoreChanged() {
    _loadEntries();
  }

  void _loadEntries() {
    if (!mounted) return;
    final store = Provider.of<OtpStore>(context, listen: false);
    final all = store.getAll();
    all.sort((a, b) =>
        a.displayName().toLowerCase().compareTo(b.displayName().toLowerCase()));
    setState(() {
      _entries
        ..clear()
        ..addAll(all);
    });
  }

  void _startTicking() {
    _ticking = true;
    Future.doWhile(() async {
      await Future.delayed(const Duration(milliseconds: 500));
      if (_ticking && mounted) {
        setState(() {});
        return true;
      }
      return false;
    });
  }

  void _showAddSheet() {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      builder: (ctx) => AddAccountSheet(
        onScan: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const ScanScreen()),
        ),
        onEnterKey: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const EnterKeyScreen()),
        ),
      ),
    );
  }

  String _computeCode(OtpEntry entry) {
    try {
      final secret = entry.decodeSecret();
      if (secret.isEmpty) return '';
      if (entry.type == OtpType.totp) {
        final seconds = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        return PasscodeGenerator.totp(
          seconds,
          secret,
          entry.algorithm,
          entry.digits,
          entry.timeStepSeconds,
        );
      } else {
        return PasscodeGenerator.hotp(
          entry.counter ?? 0,
          secret,
          entry.algorithm,
          entry.digits,
        );
      }
    } catch (_) {
      return '';
    }
  }

  Future<void> _copyCode(OtpEntry entry) async {
    final code = _computeCode(entry);
    if (code.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('生成动态口令失败，请检查密钥')),
        );
      }
      return;
    }
    await Clipboard.setData(ClipboardData(text: code));
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('已复制: $code')),
      );
    }
    if (entry.type == OtpType.hotp) {
      if (!mounted) return;
      await Provider.of<OtpStore>(context, listen: false)
          .incrementHotpCounter(entry.id);
    }
  }

  Future<void> _refreshHotp(OtpEntry entry) async {
    await Provider.of<OtpStore>(context, listen: false)
        .incrementHotpCounter(entry.id);
  }

  Future<void> _deleteEntry(OtpEntry entry) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('删除账号'),
        content: Text('确定要删除 ${entry.displayName()} 吗？'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('取消')),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('删除', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );
    if (confirmed == true && mounted) {
      await Provider.of<OtpStore>(context, listen: false).delete(entry.id);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('已删除账号')),
        );
      }
    }
  }

  Future<void> _clearAll() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('清空所有账号'),
        content: const Text('这将删除所有已保存的 OTP 账号，且无法恢复。确定继续吗？'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('取消')),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('清空', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );
    if (confirmed == true && mounted) {
      await Provider.of<OtpStore>(context, listen: false).replaceAll([]);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('已清空所有账号')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('OTP Authenticator'),
        actions: [
          if (_entries.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.delete_sweep_outlined),
              tooltip: '清空所有',
              onPressed: _clearAll,
            ),
        ],
      ),
      body: _entries.isEmpty
          ? Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(Icons.lock_clock, size: 64, color: Colors.grey.shade400),
                  const SizedBox(height: 16),
                  Text('还没有账号',
                      style:
                          TextStyle(fontSize: 18, color: Colors.grey.shade600)),
                  const SizedBox(height: 8),
                  Text(
                    '点击右下角的 + 按钮，或扫描二维码添加',
                    style:
                        TextStyle(fontSize: 14, color: Colors.grey.shade500),
                  ),
                ],
              ),
            )
          : ListView.builder(
              padding: const EdgeInsets.symmetric(vertical: 8),
              itemCount: _entries.length,
              itemBuilder: (ctx, i) {
                final e = _entries[i];
                return OtpTile(
                  key: ValueKey(e.id),
                  entry: e,
                  onCopy: () => _copyCode(e),
                  onRefreshHotp: () => _refreshHotp(e),
                  onDelete: () => _deleteEntry(e),
                  onTap: () => _copyCode(e),
                );
              },
            ),
      floatingActionButton: FloatingActionButton(
        onPressed: _showAddSheet,
        child: const Icon(Icons.add),
      ),
    );
  }
}
