import 'package:cryptography/dart.dart';
import 'package:cryptography/cryptography.dart';
import 'aes_impl.dart';
//import 'aes_impl_constants.dart' as constants;
import 'dart:typed_data';

class AesGcmUtils {
  static const _bit32 = 0x100 * 0x100 * 0x100 * 0x100;
  static int _uint32ChangeEndian(int v) {
    // We mask with 0xFFFFFFFF to ensure the compiler recognizes the value will
    // be small enough to be a 'mint'.
    return (0xFFFFFFFF & ((0xFF & v) << 24)) |
        (0xFFFFFF & ((0xFF & (v >> 8)) << 16)) |
        (0xFFFF & ((0xFF & (v >> 16)) << 8)) |
        (0xFF & (v >> 24));
  }

  /// Returns nonce as 128-bit block
  static Uint8List _nonceToBlock(
    Uint32List h,
    List<int> nonce,
  ) {
    final nonceLength = nonce.length;
    if (nonceLength == 12) {
      // If the nonce has exactly 12 bytes,
      // we just write it directly.
      final nonceBytes = Uint8List(16);
      nonceBytes.setAll(0, nonce);
      nonceBytes[nonceBytes.length - 1] = 1;
      return nonceBytes;
    }
    // Otherwise we take a hash of:
    //   nonce + padding
    //   padding (8 bytes)
    //   length of nonce in bits (uint64)
    final suffixByteData = ByteData(16);
    suffixByteData.setUint32(8, (8 * nonceLength) ~/ _bit32, Endian.big);
    suffixByteData.setUint32(12, (8 * nonceLength) % _bit32, Endian.big);
    final suffixBytes = Uint8List.view(suffixByteData.buffer);
    final result = Uint32List(4);
    _ghash(result, h, nonce);
    _ghash(result, h, suffixBytes);
    return Uint8List.view(result.buffer);
  }

  static void _ghash(Uint32List result, Uint32List h, List<int> data) {
    final tmp = ByteData(16);
    tmp.setUint32(0, 0);
    tmp.setUint32(4, 0);
    tmp.setUint32(8, 0);
    tmp.setUint32(12, 0);

    // Allocate one block
    var x0 = _uint32ChangeEndian(result[0]);
    var x1 = _uint32ChangeEndian(result[1]);
    var x2 = _uint32ChangeEndian(result[2]);
    var x3 = _uint32ChangeEndian(result[3]);
    final h0 = h[0];
    final h1 = h[1];
    final h2 = h[2];
    final h3 = h[3];

    // For each
    for (var i = 0; i < data.length; i += 16) {
      if (i + 16 <= data.length) {
        for (var j = 0; j < 16; j++) {
          tmp.setUint8(j, data[i + j]);
        }
      } else {
        tmp.setUint32(0, 0);
        tmp.setUint32(4, 0);
        tmp.setUint32(8, 0);
        tmp.setUint32(12, 0);
        final n = data.length % 16;
        for (var j = 0; j < n; j++) {
          tmp.setUint8(j, data[i + j]);
        }
      }

      // result ^= x_i
      x0 ^= tmp.getUint32(0, Endian.big);
      x1 ^= tmp.getUint32(4, Endian.big);
      x2 ^= tmp.getUint32(8, Endian.big);
      x3 ^= tmp.getUint32(12, Endian.big);

      var z0 = 0;
      var z1 = 0;
      var z2 = 0;
      var z3 = 0;

      var hi = h0;
      for (var i = 0; i < 128; i++) {
        // Get bit `i` of `h`
        if (i % 32 == 0 && i != 0) {
          if (i == 32) {
            hi = h1;
          } else if (i == 64) {
            hi = h2;
          } else {
            hi = h3;
          }
        }
        final hBit = hi & (1 << (31 - i % 32));
        if (hBit != 0) {
          z0 ^= x0;
          z1 ^= x1;
          z2 ^= x2;
          z3 ^= x3;
        }

        var carry = 0;
        final tmp0 = x0;
        x0 = carry | (tmp0 >> 1);
        carry = 0xFFFFFFFF & ((0x1 & tmp0) << 31);

        final tmp1 = x1;
        x1 = carry | (tmp1 >> 1);
        carry = 0xFFFFFFFF & ((0x1 & tmp1) << 31);

        final tmp2 = (x2);
        x2 = carry | (tmp2 >> 1);
        carry = 0xFFFFFFFF & ((0x1 & tmp2) << 31);

        final tmp3 = (x3);
        x3 = carry | (tmp3 >> 1);
        carry = 0xFFFFFFFF & ((0x1 & tmp3) << 31);

        if (carry != 0) {
          x0 ^= 0xe1000000;
        }
      }
      x0 = z0;
      x1 = z1;
      x2 = z2;
      x3 = z3;
    }
    result[0] = _uint32ChangeEndian(x0);
    result[1] = _uint32ChangeEndian(x1);
    result[2] = _uint32ChangeEndian(x2);
    result[3] = _uint32ChangeEndian(x3);
  }

  static Future<Mac> calculateMac(cipherData, secretKey, nonce, aad) async {
    Mac gmac = Mac.empty;
    try {
      final secretKeyData = await secretKey.extract();
      final expandedKey = aesExpandKeyForEncrypting(secretKeyData);
      final h = Uint32List(4);
      aesEncryptBlock(h, 0, h, 0, expandedKey);
      h[0] = _uint32ChangeEndian(h[0]);
      h[1] = _uint32ChangeEndian(h[1]);
      h[2] = _uint32ChangeEndian(h[2]);
      h[3] = _uint32ChangeEndian(h[3]);
      // Calculate initial nonce
      var stateBytes = _nonceToBlock(h, nonce);
      var state = Uint32List.view(stateBytes.buffer);
      gmac = DartGcm().calculateMacSync(
        cipherData,
        aad: aad,
        expandedKey: expandedKey,
        h: h,
        precounterBlock: state,
      );
    } catch (e) {
      print('decrypt error_ $e');
    }
    return gmac;
  }
}
