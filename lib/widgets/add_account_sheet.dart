import 'package:flutter/material.dart';

/// 添加账号底部弹窗：选择扫码或手动输入
class AddAccountSheet extends StatelessWidget {
  final VoidCallback onScan;
  final VoidCallback onEnterKey;

  const AddAccountSheet({
    super.key,
    required this.onScan,
    required this.onEnterKey,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: const BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 40,
            height: 4,
            decoration: BoxDecoration(
              color: Colors.grey.shade300,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          const SizedBox(height: 20),
          const Text(
            '添加账号',
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 20),
          ListTile(
            leading: CircleAvatar(
              backgroundColor: Colors.blue.shade50,
              child: const Icon(Icons.qr_code_scanner, color: Colors.blue),
            ),
            title: const Text('扫描二维码'),
            subtitle: const Text('扫描 otpauth 二维码快速添加'),
            onTap: () {
              Navigator.pop(context);
              onScan();
            },
          ),
          ListTile(
            leading: CircleAvatar(
              backgroundColor: Colors.green.shade50,
              child: const Icon(Icons.keyboard, color: Colors.green),
            ),
            title: const Text('手动输入密钥'),
            subtitle: const Text('手动输入 Base32 密钥'),
            onTap: () {
              Navigator.pop(context);
              onEnterKey();
            },
          ),
          const SizedBox(height: 12),
        ],
      ),
    );
  }
}
