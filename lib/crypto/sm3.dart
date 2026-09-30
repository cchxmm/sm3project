import 'dart:typed_data';

/// SM3 国密哈希算法（GM/T 0004-2012 标准），纯 Dart 实现。
///
/// 输出 256 位（32 字节）哈希值。用于 HMAC-SM3 动态口令算法。
/// 实现参考 GMT 0021-2023《动态口令密码应用技术规范》。
class Sm3 {
  static const int _blockSize = 64; // 512 bit = 64 byte

  // 初始值 IV
  static final List<int> _iv = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, //
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
  ];

  Sm3._();

  /// 计算消息的 SM3 哈希值，返回 32 字节
  static List<int> hash(List<int> message) {
    final padded = _pad(message);
    final v = List<int>.from(_iv);

    for (int offset = 0; offset < padded.length; offset += _blockSize) {
      final block = padded.sublist(offset, offset + _blockSize);
      _compress(v, block);
    }

    final result = Uint8List(32);
    final bd = ByteData.view(result.buffer);
    for (int i = 0; i < 8; i++) {
      bd.setUint32(i * 4, v[i]);
    }
    return result;
  }

  /// HMAC-SM3：使用 SM3 作为底层哈希的 HMAC 运算
  static List<int> hmac(List<int> key, List<int> data) {
    // HMAC: H(K XOR opad, H(K XOR ipad, data))
    const int blockSize = _blockSize;

    // 如果密钥长度大于块大小，先哈希
    List<int> k = key;
    if (k.length > blockSize) {
      k = hash(k);
    }
    // 不足块大小用 0 填充
    if (k.length < blockSize) {
      k = [...k, ...List<int>.filled(blockSize - k.length, 0)];
    }

    final ipad = List<int>.generate(blockSize, (i) => k[i] ^ 0x36);
    final opad = List<int>.generate(blockSize, (i) => k[i] ^ 0x5C);

    final inner = hash([...ipad, ...data]);
    return hash([...opad, ...inner]);
  }

  // 消息填充：在消息末尾添加 0x80，然后填 0，最后 8 字节为消息长度（bit）
  static List<int> _pad(List<int> msg) {
    final len = msg.length;
    final bitLen = len * 8;

    final padLen = (len % 64 < 56) ? (56 - len % 64) : (120 - len % 64);
    final padded = Uint8List(len + padLen + 8);
    padded.setAll(0, msg);
    padded[len] = 0x80;
    // 其余默认 0
    // 最后 8 字节为长度（大端序）
    final bd = ByteData.view(padded.buffer);
    bd.setUint32(padded.length - 8, 0); // 高 32 位（消息通常不超过 2^32 字节）
    bd.setUint32(padded.length - 4, bitLen);
    return padded;
  }

  static int _rotl(int x, int n) {
    n = n % 32;
    x = x & 0xFFFFFFFF;
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF;
  }

  static int _p0(int x) => x ^ _rotl(x, 9) ^ _rotl(x, 17);
  static int _p1(int x) => x ^ _rotl(x, 15) ^ _rotl(x, 23);

  static int _ff(int x, int y, int z, int j) {
    if (j < 16) {
      return x ^ y ^ z;
    }
    return (x & y) | (x & z) | (y & z);
  }

  static int _gg(int x, int y, int z, int j) {
    if (j < 16) {
      return x ^ y ^ z;
    }
    return (x & y) | ((~x) & z);
  }

  static int _tj(int j) => j < 16 ? 0x79CC4519 : 0x7A879D8A;

  static void _compress(List<int> v, List<int> block) {
    final bd = ByteData.view(Uint8List.fromList(block).buffer);
    final w = List<int>.filled(68, 0);
    final w1 = List<int>.filled(64, 0);

    // 消息扩展：W0..W67
    for (int i = 0; i < 16; i++) {
      w[i] = bd.getUint32(i * 4);
    }
    for (int j = 16; j < 68; j++) {
      w[j] = _p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15)) ^
          _rotl(w[j - 13], 7) ^
          w[j - 6];
    }
    for (int j = 0; j < 64; j++) {
      w1[j] = w[j] ^ w[j + 4];
    }

    // 压缩
    int a = v[0], b = v[1], c = v[2], d = v[3];
    int e = v[4], f = v[5], g = v[6], h = v[7];

    for (int j = 0; j < 64; j++) {
      final ss1 = _rotl((_rotl(a, 12) + e + _rotl(_tj(j), j)) & 0xFFFFFFFF, 7);
      final ss2 = ss1 ^ _rotl(a, 12);
      final tt1 = (_ff(a, b, c, j) + d + ss2 + w1[j]) & 0xFFFFFFFF;
      final tt2 = (_gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF;
      d = c;
      c = _rotl(b, 9);
      b = a;
      a = tt1;
      h = g;
      g = _rotl(f, 19);
      f = e;
      e = _p0(tt2);
    }

    v[0] = (a ^ v[0]) & 0xFFFFFFFF;
    v[1] = (b ^ v[1]) & 0xFFFFFFFF;
    v[2] = (c ^ v[2]) & 0xFFFFFFFF;
    v[3] = (d ^ v[3]) & 0xFFFFFFFF;
    v[4] = (e ^ v[4]) & 0xFFFFFFFF;
    v[5] = (f ^ v[5]) & 0xFFFFFFFF;
    v[6] = (g ^ v[6]) & 0xFFFFFFFF;
    v[7] = (h ^ v[7]) & 0xFFFFFFFF;
  }
}
