import 'package:flutter/material.dart';
import '../models/otp_entry.dart';
import '../models/otp_type.dart';
import '../crypto/passcode_generator.dart';

/// OTP 列表项，展示账号名、当前口令、倒计时进度条
class OtpTile extends StatelessWidget {
  final OtpEntry entry;
  final VoidCallback onCopy;
  final VoidCallback onRefreshHotp;
  final VoidCallback onDelete;
  final VoidCallback onTap;

  const OtpTile({
    super.key,
    required this.entry,
    required this.onCopy,
    required this.onRefreshHotp,
    required this.onDelete,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final code = _computeCode();
    final isTotp = entry.type == OtpType.totp;
    final remaining = isTotp ? _millisUntilNextStep() : 0;
    final step = entry.timeStepSeconds > 0 ? entry.timeStepSeconds : 30;
    final progress = isTotp ? (1.0 - remaining / (step * 1000)) : 0.0;

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  CircleAvatar(
                    radius: 20,
                    backgroundColor: Colors.blue.shade100,
                    child: Text(
                      entry.initials(),
                      style: const TextStyle(
                        fontWeight: FontWeight.bold,
                        color: Colors.blue,
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          entry.name.isEmpty
                              ? (entry.issuer?.isEmpty ?? true)
                                  ? '（未命名）'
                                  : entry.issuer!
                              : entry.name,
                          style: const TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Text(
                          '${entry.type.canonical.toUpperCase()} · ${entry.algorithm.canonical} · ${entry.digits}位',
                          style: TextStyle(
                            fontSize: 12,
                            color: Colors.grey.shade600,
                          ),
                        ),
                      ],
                    ),
                  ),
                  PopupMenuButton<String>(
                    onSelected: (value) {
                      if (value == 'delete') onDelete();
                    },
                    itemBuilder: (context) => [
                      const PopupMenuItem(
                        value: 'delete',
                        child: Row(
                          children: [
                            Icon(Icons.delete_outline, size: 20),
                            SizedBox(width: 8),
                            Text('删除账号'),
                          ],
                        ),
                      ),
                    ],
                  ),
                ],
              ),
              const SizedBox(height: 8),
              InkWell(
                onTap: onCopy,
                borderRadius: BorderRadius.circular(8),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  decoration: BoxDecoration(
                    color: Colors.grey.shade100,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    children: [
                      Expanded(
                        child: Text(
                          _formatCode(code),
                          style: TextStyle(
                            fontSize: 28,
                            fontWeight: FontWeight.bold,
                            letterSpacing: 3,
                            color: code.isEmpty ? Colors.grey : Colors.black,
                          ),
                        ),
                      ),
                      Icon(Icons.copy, size: 20, color: Colors.grey.shade600),
                    ],
                  ),
                ),
              ),
              if (isTotp) ...[
                const SizedBox(height: 8),
                ClipRRect(
                  borderRadius: BorderRadius.circular(4),
                  child: LinearProgressIndicator(
                    value: progress.clamp(0.0, 1.0),
                    minHeight: 4,
                    backgroundColor: Colors.grey.shade200,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  '${(remaining ~/ 1000) + 1}s',
                  style: TextStyle(fontSize: 11, color: Colors.grey.shade600),
                ),
              ] else ...[
                const SizedBox(height: 8),
                Row(
                  children: [
                    Text(
                      'counter ${entry.counter ?? 0}',
                      style: TextStyle(fontSize: 11, color: Colors.grey.shade600),
                    ),
                    const Spacer(),
                    TextButton.icon(
                      onPressed: onRefreshHotp,
                      icon: const Icon(Icons.refresh, size: 16),
                      label: const Text('刷新', style: TextStyle(fontSize: 12)),
                    ),
                  ],
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  String _computeCode() {
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

  int _millisUntilNextStep() {
    final step = entry.timeStepSeconds > 0 ? entry.timeStepSeconds : 30;
    final now = DateTime.now().millisecondsSinceEpoch;
    final mod = now % (step * 1000);
    return step * 1000 - mod;
  }

  String _formatCode(String code) {
    if (code.isEmpty) return '------';
    if (code.length <= 4) return code;
    final mid = code.length ~/ 2;
    return '${code.substring(0, mid)} ${code.substring(mid)}';
  }
}
