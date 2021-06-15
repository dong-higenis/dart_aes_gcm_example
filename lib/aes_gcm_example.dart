import 'package:cryptography/cryptography.dart';
import 'custom/aes_utils.dart';

Future<void> normalExample() async {
  // 암호키
  final key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
  // 1회용 키
  final nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
  // 인증용 데이터
  final aad = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

  // 암호화할 데이터
  final plainText = [1, 2, 3];

  // AES GCM 128 알고리즘 사용
  final algorithm = AesGcm.with128bits();

  // 키를 SecretKey로 생성
  final secretKey = SecretKey(key);

  // 암호화!
  final secretBox = await algorithm.encrypt(plainText,
      secretKey: secretKey, nonce: nonce, aad: aad);

  // 암호화된 데이터
  print('Ciphertext: ${secretBox.cipherText}');
  // 암호화된 유효성 검사용 MAC 데이터
  print('MAC: ${secretBox.mac}');

  // 복호화 시작
  // secretKey와 aad 공통으로 사용
  var decryptedData = <int>[];
  try {
    // 복호화
    decryptedData = await algorithm.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: aad,
    );
  } catch (e) {
    print('decryption error: $e');
  } finally {
    //복호화 성공시!
    print('decryptedData: $decryptedData');
  }
}

bool equals(List<int> left, List<int> right) {
  if (left.length != right.length) {
    return false;
  }
  var result = 0;
  for (var i = 0; i < left.length; i++) {
    result |= (left[i] ^ right[i]);
  }
  return result == 0;
}

Future<void> customMacLengthExample({int macLength = 16}) async {
  print('\n\nStart customMacLengthExample');

  // 암호키
  final key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
  // 1회용 키
  final nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
  // 인증용 데이터
  final aad = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

  // 암호화할 데이터
  final plainText = [1, 2, 3];

  // AES GCM 128 알고리즘 사용
  final algorithm = AesGcm.with128bits();

  // 키를 SecretKey로 생성
  final secretKey = SecretKey(key);

  // 암호화!
  final secretBox = await algorithm.encrypt(plainText,
      secretKey: secretKey, nonce: nonce, aad: aad);

  // 암호화된 데이터
  print('Ciphertext: ${secretBox.cipherText}');
  // 암호화된 유효성 검사용 MAC 데이터
  print('MAC: ${secretBox.mac}');

  // MAC 데이터를 먼저 계산한다.
  final mac = await AesGcmUtils.calculateMac(
      secretBox.cipherText, secretKey, nonce, aad);

  // 계산된 MAC데이터와 암호화된 MAC 데이터가 같은이 비교, 이때 길이를 지정하여 비교한다.
  // constantTimeBytesEquality는 cryptography/helpers.dart 제공하는 클래스
  if (!equals(mac.bytes.sublist(0, macLength),
      secretBox.mac.bytes.sublist(0, macLength))) {
    // 유효성 검사 실패!, 데이터가 손상됨
    print('It has wrong message authentication code (MAC)');
    return;
  }

  //새로 계산된 mac으로 SecretBox 생성
  final newSecretBox = SecretBox(secretBox.cipherText, nonce: nonce, mac: mac);

  // 복호화 시작
  // secretKey와 aad 공통으로 사용
  var decryptedData = <int>[];
  decryptedData = await algorithm.decrypt(
    newSecretBox,
    secretKey: secretKey,
    aad: aad,
  );

  try {
    // 복호화
    decryptedData = await algorithm.decrypt(
      newSecretBox,
      secretKey: secretKey,
      aad: aad,
    );
  } catch (e) {
    print('decryption error: $e');
  } finally {
    //복호화 성공시!
    print('decryptedData: $decryptedData');
  }
}
