import 'package:aes_gcm_example/aes_gcm_example.dart' as aes_gcm_example;

Future<void> main() async {
  await aes_gcm_example.normalExample();
  await aes_gcm_example.customMacLengthExample(macLength: 4);
}
