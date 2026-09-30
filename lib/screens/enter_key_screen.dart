import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../models/hash_algorithm.dart';
import '../models/otp_entry.dart';
import '../models/otp_type.dart';
import '../services/otp_store.dart';
import '../crypto/base32.dart';
import '../crypto/passcode_generator.dart';

class EnterKeyScreen extends StatefulWidget {
  const EnterKeyScreen({super.key});

  @override
  State<EnterKeyScreen> createState() => _EnterKeyScreenState();
}

class _EnterKeyScreenState extends State<EnterKeyScreen> {
  final _formKey = GlobalKey<FormState>();
  final _nameController = TextEditingController();
  final _secretController = TextEditingController();

  OtpType _selectedType = OtpType.totp;
  int _algoIndex = 0;
  int _digitsIndex = 0;
  int _periodIndex = 0;
  String? _previewCode;

  static const _algoLabels = [
    'HMAC-SHA1',
    'HMAC-SHA256',
    'HMAC-SHA512',
    'HMAC-SHA224',
    'HMAC-SHA384',
    'HMAC-MD5',
    'HMAC-SM3 (国密)',
    'CBC-SM4 (国密)',
  ];

  @override
  void dispose() {
    _nameController.dispose();
    _secretController.dispose();
    super.dispose();
  }

  HashAlgorithm get _selectedAlgo => HashAlgorithm.fromIndex(_algoIndex);
  int get _selectedDigits => _digitsIndex == 1 ? 7 : (_digitsIndex == 2 ? 8 : 6);
  int get _selectedPeriod => _periodIndex == 1 ? 60 : 30;

  void _formatSecret(String value) {
    final raw = value.toUpperCase().replaceAll(RegExp(r'[^A-Z2-7]'), '');
    final sb = StringBuffer();
    for (int i = 0; i < raw.length; i++) {
      if (i > 0 && i % 4 == 0) sb.write(' ');
      sb.write(raw[i]);
    }
    final formatted = sb.toString();
    if (_secretController.text != formatted) {
      _secretController.value = TextEditingValue(
        text: formatted,
        selection: TextSelection.collapsed(offset: formatted.length),
      );
    }
  }

  void _preview() {
    final secret = _secretController.text.replaceAll(' ', '');
    if (secret.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('请输入共享密钥')),
      );
      return;
    }
    List<int> key;
    try {
      key = Base32.decode(secret);
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('密钥格式错误: $e')),
      );
      return;
    }
    final algo = _selectedAlgo;
    final digits = _selectedDigits;
    final type = _selectedType;
    String code;
    if (type == OtpType.totp) {
      final seconds = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      code = PasscodeGenerator.totp(
          seconds, key, algo, digits, _selectedPeriod);
    } else {
      code = PasscodeGenerator.hotp(0, key, algo, digits);
    }
    setState(() => _previewCode = code);
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('当前口令: $code')),
    );
  }

  Future<void> _save() async {
    if (!_formKey.currentState!.validate()) return;
    final name = _nameController.text.trim();
    final secret = _secretController.text.replaceAll(' ', '');

    if (name.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('请填写账号名称')),
      );
      return;
    }
    if (secret.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('请输入共享密钥')),
      );
      return;
    }
    List<int> key;
    try {
      key = Base32.decode(secret);
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('密钥格式错误: $e')),
      );
      return;
    }
    if (key.length < 10) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('密钥过短（至少 10 个 Base32 字符）')),
      );
      return;
    }

    final entry = OtpEntry(
      name: name,
      secret: secret,
      type: _selectedType,
      counter: _selectedType == OtpType.hotp ? 0 : null,
      algorithm: _selectedAlgo,
      digits: _selectedDigits,
      timeStepSeconds: _selectedPeriod,
    );
    await Provider.of<OtpStore>(context, listen: false).save(entry);
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('账号已添加')),
    );
    Navigator.pop(context);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('手动输入密钥'),
      ),
      body: Form(
        key: _formKey,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            TextFormField(
              controller: _nameController,
              decoration: const InputDecoration(
                labelText: '账号名称',
                border: OutlineInputBorder(),
              ),
              validator: (v) =>
                  (v == null || v.trim().isEmpty) ? '请填写账号名称' : null,
            ),
            const SizedBox(height: 16),
            TextFormField(
              controller: _secretController,
              decoration: const InputDecoration(
                labelText: '共享密钥 (Base32)',
                border: OutlineInputBorder(),
              ),
              onChanged: _formatSecret,
              validator: (v) => (v == null || v.replaceAll(' ', '').isEmpty)
                  ? '请输入共享密钥'
                  : null,
            ),
            const SizedBox(height: 16),
            DropdownButtonFormField<OtpType>(
              value: _selectedType,
              decoration: const InputDecoration(
                labelText: '类型',
                border: OutlineInputBorder(),
              ),
              items: const [
                DropdownMenuItem(value: OtpType.totp, child: Text('基于时间 (TOTP)')),
                DropdownMenuItem(value: OtpType.hotp, child: Text('基于计数器 (HOTP)')),
              ],
              onChanged: (v) => setState(() => _selectedType = v ?? OtpType.totp),
            ),
            const SizedBox(height: 16),
            DropdownButtonFormField<int>(
              value: _algoIndex,
              decoration: const InputDecoration(
                labelText: '算法',
                border: OutlineInputBorder(),
              ),
              items: List.generate(_algoLabels.length, (i) =>
                  DropdownMenuItem(value: i, child: Text(_algoLabels[i]))),
              onChanged: (v) => setState(() => _algoIndex = v ?? 0),
            ),
            const SizedBox(height: 16),
            DropdownButtonFormField<int>(
              value: _digitsIndex,
              decoration: const InputDecoration(
                labelText: '位数',
                border: OutlineInputBorder(),
              ),
              items: const [
                DropdownMenuItem(value: 0, child: Text('6 位')),
                DropdownMenuItem(value: 1, child: Text('7 位')),
                DropdownMenuItem(value: 2, child: Text('8 位')),
              ],
              onChanged: (v) => setState(() => _digitsIndex = v ?? 0),
            ),
            if (_selectedType == OtpType.totp) ...[
              const SizedBox(height: 16),
              DropdownButtonFormField<int>(
                value: _periodIndex,
                decoration: const InputDecoration(
                  labelText: '时间步长',
                  border: OutlineInputBorder(),
                ),
                items: const [
                  DropdownMenuItem(value: 0, child: Text('30 秒')),
                  DropdownMenuItem(value: 1, child: Text('60 秒')),
                ],
                onChanged: (v) => setState(() => _periodIndex = v ?? 0),
              ),
            ],
            if (_previewCode != null) ...[
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.green.shade50,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Colors.green.shade200),
                ),
                child: Column(
                  children: [
                    const Text('预览口令', style: TextStyle(fontSize: 12)),
                    const SizedBox(height: 4),
                    Text(
                      _previewCode!,
                      style: const TextStyle(
                        fontSize: 32,
                        fontWeight: FontWeight.bold,
                        letterSpacing: 4,
                      ),
                    ),
                  ],
                ),
              ),
            ],
            const SizedBox(height: 24),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: _preview,
                    child: const Text('预览口令'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton(
                    onPressed: _save,
                    child: const Text('添加'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
