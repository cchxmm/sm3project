import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:provider/provider.dart';

import '../services/otp_store.dart';
import '../services/otp_uri.dart';

class ScanScreen extends StatefulWidget {
  const ScanScreen({super.key});

  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  final MobileScannerController _controller = MobileScannerController(
    detectionSpeed: DetectionSpeed.normal,
    facing: CameraFacing.back,
  );
  bool _scanned = false;
  String _hint = '将二维码对准摄像头';

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_scanned) return;
    for (final barcode in capture.barcodes) {
      final raw = barcode.rawValue;
      if (raw == null || raw.isEmpty) continue;

      _scanned = true;
      final result = OtpUri.parseAny(raw.trim());
      if (result.isSuccess) {
        _handleSuccess(result);
      } else {
        _scanned = false;
        _handleFailure(raw, result);
      }
      return;
    }
  }

  Future<void> _handleSuccess(OtpUriResult result) async {
    final store = Provider.of<OtpStore>(context, listen: false);
    for (final entry in result.entries) {
      await store.save(entry);
    }
    final msg = result.entries.length == 1
        ? '已识别并添加账号: ${result.entries[0].displayName()}'
        : '已识别并导入 ${result.entries.length} 个账号';
    if (!mounted) return;
    setState(() => _hint = msg);
    await Future.delayed(const Duration(seconds: 1));
    if (mounted) Navigator.pop(context);
  }

  void _handleFailure(String raw, OtpUriResult result) {
    final preview = raw.length > 100 ? '${raw.substring(0, 100)}…' : raw;
    final cleanPreview = preview.replaceAll('\n', ' ').replaceAll('\r', ' ');
    final message = result.otpLike && result.error != null
        ? '无法导入: ${result.error}\n识别到的内容: $cleanPreview'
        : '该二维码不是动态口令（otpauth）二维码\n识别到的内容: $cleanPreview';
    setState(() => _hint = message);
    Future.delayed(const Duration(seconds: 6), () {
      if (mounted) setState(() => _hint = '将二维码对准摄像头');
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('扫描二维码'),
      ),
      body: Stack(
        children: [
          MobileScanner(
            controller: _controller,
            onDetect: _onDetect,
          ),
          Positioned(
            bottom: 40,
            left: 0,
            right: 0,
            child: Container(
              margin: const EdgeInsets.symmetric(horizontal: 24),
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              decoration: BoxDecoration(
                color: Colors.black54,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text(
                _hint,
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.white, fontSize: 14),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
