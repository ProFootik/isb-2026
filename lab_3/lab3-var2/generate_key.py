import argparse
import json
from asymmetric import RSACipher
from symmetric import CamelliaCipher


def main():
    parser = argparse.ArgumentParser(description='Генерация ключей для гибридной криптосистемы')
    parser.add_argument('--public', '-pub', required=True, help='Путь для сохранения открытого ключа RSA')
    parser.add_argument('--private', '-priv', required=True, help='Путь для сохранения закрытого ключа RSA')
    parser.add_argument('--enc-sym', '-e', required=True, help='Путь для сохранения зашифрованного симметричного ключа')
    parser.add_argument('--key-size', '-k', type=int, choices=[128, 192, 256], default=256, 
                       help='Длина ключа Camellia (128, 192, 256 бит)')
    
    args = parser.parse_args()
    
    print("=== Генерация ключей гибридной системы ===")
    
    print("1. Генерация ключа Camellia-{}...".format(args.key_size))
    sym_key = CamelliaCipher.generate_key(args.key_size)
    print("   Симметричный ключ: {}...".format(sym_key.hex()[:32]))
    
    print("2. Генерация пары ключей RSA (2048 бит)...")
    rsa_cipher = RSACipher(2048)
    private_key, public_key = rsa_cipher.generate_keys()
    print("   Ключи RSA сгенерированы")
    
    print("3. Сохранение открытого ключа: {}".format(args.public))
    rsa_cipher.save_public_key(args.public)
    
    print("4. Сохранение закрытого ключа: {}".format(args.private))
    rsa_cipher.save_private_key(args.private)
    
    print("5. Шифрование симметричного ключа открытым ключом RSA...")
    encrypted_sym_key = RSACipher.encrypt(public_key, sym_key)
    
    key_data = {
        'encrypted_key': encrypted_sym_key.hex(),
        'key_size': args.key_size
    }
    
    print("6. Сохранение зашифрованного ключа: {}".format(args.enc_sym))
    with open(args.enc_sym, 'w') as f:
        json.dump(key_data, f, indent=2)
    
    print("\nГенерация ключей успешно завершена!")
    print("\nСгенерированные файлы:")
    print("  - Открытый ключ RSA: {}".format(args.public))
    print("  - Закрытый ключ RSA: {}".format(args.private))
    print("  - Зашифрованный ключ Camellia: {}".format(args.enc_sym))


if __name__ == "__main__":
    main()