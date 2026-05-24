import argparse
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


class HybridCryptoSystem:
    """Гибридная криптосистема с Camellia (симметричный) и RSA (асимметричный)"""
    
    BLOCK_SIZE = 16
    
    @staticmethod
    def generate_keys(public_key_path, private_key_path, encrypted_sym_key_path, sym_key_size=256):
        """Генерация ключей гибридной системы.
        
        Принимает:
            public_key_path: путь для сохранения открытого ключа RSA
            private_key_path: путь для сохранения закрытого ключа RSA
            encrypted_sym_key_path: путь для сохранения зашифрованного ключа Camellia
            sym_key_size: длина ключа Camellia (128/192/256)
        
        Возвращает: True при успехе
        """
        print("\n=== РЕЖИМ ГЕНЕРАЦИИ КЛЮЧЕЙ ===")
        
        print("1.1. Генерация ключа Camellia (длина {} бит)...".format(sym_key_size))
        sym_key_size_bytes = sym_key_size // 8
        symmetric_key = os.urandom(sym_key_size_bytes)
        print("     Симметричный ключ сгенерирован: {}".format(symmetric_key.hex()[:16] + "..."))
        
        print("1.2. Генерация пары ключей RSA (2048 бит)...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        print("     Пара ключей RSA успешно сгенерирована")
        
        print("1.3. Сохранение ключей RSA...")
        
        with open(public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("     Открытый ключ сохранен: {}".format(public_key_path))
        
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print("     Закрытый ключ сохранен: {}".format(private_key_path))
        
        print("1.4. Шифрование симметричного ключа открытым ключом RSA...")
        encrypted_sym_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        key_data = {
            'encrypted_key': encrypted_sym_key.hex(),
            'key_size': sym_key_size
        }
        with open(encrypted_sym_key_path, 'w') as f:
            json.dump(key_data, f)
        print("     Зашифрованный симметричный ключ сохранен: {}".format(encrypted_sym_key_path))
        
        print("\nГенерация ключей успешно завершена!")
        return True
    
    @staticmethod
    def load_symmetric_key(encrypted_sym_key_path, private_key_path):
        """Загрузка и расшифровка симметричного ключа.
        
        Принимает:
            encrypted_sym_key_path: путь к зашифрованному ключу
            private_key_path: путь к закрытому ключу RSA
        
        Возвращает: (symmetric_key_bytes, key_size_in_bits)
        """
        with open(encrypted_sym_key_path, 'r') as f:
            key_data = json.load(f)
        
        encrypted_key = bytes.fromhex(key_data['encrypted_key'])
        key_size = key_data['key_size']
        
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        
        symmetric_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return symmetric_key, key_size
    
    @staticmethod
    def encrypt_file(input_file_path, output_file_path, encrypted_sym_key_path, private_key_path):
        """Шифрование файла.
        
        Принимает:
            input_file_path: путь к исходному файлу
            output_file_path: путь для сохранения зашифрованного файла
            encrypted_sym_key_path: путь к зашифрованному ключу
            private_key_path: путь к закрытому ключу RSA
        
        Возвращает: True при успехе
        """
        print("\n=== РЕЖИМ ШИФРОВАНИЯ ===")
        
        print("2.1. Расшифровка симметричного ключа...")
        symmetric_key, key_size = HybridCryptoSystem.load_symmetric_key(
            encrypted_sym_key_path, private_key_path
        )
        print("     Симметричный ключ (Camellia-{}) загружен и расшифрован".format(key_size))
        
        print("2.2. Шифрование файла: {}".format(input_file_path))
        
        with open(input_file_path, 'rb') as f:
            plaintext = f.read()
        
        print("     Размер исходного файла: {} байт".format(len(plaintext)))
        
        iv = os.urandom(HybridCryptoSystem.BLOCK_SIZE)
        
        cipher = Cipher(algorithms.Camellia(symmetric_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        padder = sym_padding.ANSIX923(HybridCryptoSystem.BLOCK_SIZE * 8).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        with open(output_file_path, 'wb') as f:
            f.write(iv + ciphertext)
        
        print("     Размер зашифрованного файла: {} байт".format(len(iv) + len(ciphertext)))
        print("     Зашифрованный файл сохранен: {}".format(output_file_path))
        
        print("\nШифрование успешно завершено!")
        return True
    
    @staticmethod
    def decrypt_file(encrypted_file_path, output_file_path, encrypted_sym_key_path, private_key_path):
        """Дешифрование файла.
        
        Принимает:
            encrypted_file_path: путь к зашифрованному файлу
            output_file_path: путь для сохранения расшифрованного файла
            encrypted_sym_key_path: путь к зашифрованному ключу
            private_key_path: путь к закрытому ключу RSA
        
        Возвращает: True при успехе
        """
        print("\n=== РЕЖИМ ДЕШИФРОВАНИЯ ===")
        
        print("3.1. Расшифровка симметричного ключа...")
        symmetric_key, key_size = HybridCryptoSystem.load_symmetric_key(
            encrypted_sym_key_path, private_key_path
        )
        print("     Симметричный ключ (Camellia-{}) загружен и расшифрован".format(key_size))
        
        print("3.2. Дешифрование файла: {}".format(encrypted_file_path))
        
        with open(encrypted_file_path, 'rb') as f:
            data = f.read()
        
        iv = data[:HybridCryptoSystem.BLOCK_SIZE]
        ciphertext = data[HybridCryptoSystem.BLOCK_SIZE:]
        
        print("     Размер зашифрованного файла: {} байт".format(len(data)))
        
        cipher = Cipher(algorithms.Camellia(symmetric_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = sym_padding.ANSIX923(HybridCryptoSystem.BLOCK_SIZE * 8).unpadder()
        plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        with open(output_file_path, 'wb') as f:
            f.write(plaintext)
        
        print("     Размер расшифрованного файла: {} байт".format(len(plaintext)))
        print("     Расшифрованный файл сохранен: {}".format(output_file_path))
        
        print("\nДешифрование успешно завершено!")
        return True


def load_settings(settings_path):
    """Загрузка настроек из JSON файла.
    
    Принимает: путь к файлу настроек
    Возвращает: словарь с настройками или None
    """
    if os.path.exists(settings_path):
        with open(settings_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


def save_settings(settings_path, settings):
    """Сохранение настроек в JSON файл.
    
    Принимает: путь к файлу и словарь с настройками
    Возвращает: None
    """
    with open(settings_path, 'w', encoding='utf-8') as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)


def interactive_mode():
    """Интерактивный режим с меню.
    
    Принимает: None
    Возвращает: None
    """
    print("\n" + "="*60)
    print("ГИБРИДНАЯ КРИПТОСИСТЕМА (Camellia + RSA)")
    print("="*60)
    
    settings_file = 'settings.json'
    settings = load_settings(settings_file)
    
    if settings:
        print("\nНайдены сохраненные настройки в {}:".format(settings_file))
        for key, value in settings.items():
            print("  {}: {}".format(key, value))
        use_saved = input("\nИспользовать сохраненные настройки? (y/n): ").lower()
        if use_saved != 'y':
            settings = None
    
    if not settings:
        settings = {}
        print("\nВведите пути к файлам (можно оставить пустым для значения по умолчанию):")
        
        settings['public_key'] = input("Путь для открытого ключа RSA [public.pem]: ") or "public.pem"
        settings['private_key'] = input("Путь для закрытого ключа RSA [private.pem]: ") or "private.pem"
        settings['encrypted_sym_key'] = input("Путь для зашифрованного симметричного ключа [sym_key.enc]: ") or "sym_key.enc"
        settings['input_file'] = input("Путь к исходному файлу [input.txt]: ") or "input.txt"
        settings['encrypted_file'] = input("Путь для зашифрованного файла [encrypted.bin]: ") or "encrypted.bin"
        settings['decrypted_file'] = input("Путь для расшифрованного файла [decrypted.txt]: ") or "decrypted.txt"
        
        save_settings(settings_file, settings)
        print("\nНастройки сохранены в {}".format(settings_file))
    
    while True:
        print("\n" + "-"*40)
        print("Выберите режим работы:")
        print("  1. Генерация ключей")
        print("  2. Шифрование файла")
        print("  3. Дешифрование файла")
        print("  4. Изменить настройки")
        print("  5. Выход")
        
        choice = input("\nВаш выбор (1-5): ").strip()
        
        match choice:
            case '1':
                print("\nДоступные длины ключа Camellia: 128, 192, 256 бит")
                while True:
                    try:
                        key_size = int(input("Введите длину ключа [256]: ") or "256")
                        if key_size in [128, 192, 256]:
                            break
                        print("Ошибка! Длина ключа должна быть 128, 192 или 256")
                    except ValueError:
                        print("Ошибка! Введите число")
                
                HybridCryptoSystem.generate_keys(
                    settings['public_key'],
                    settings['private_key'],
                    settings['encrypted_sym_key'],
                    key_size
                )
                
            case '2':
                if not os.path.exists(settings['encrypted_sym_key']):
                    print("Ошибка: файл с зашифрованным ключом не найден: {}".format(settings['encrypted_sym_key']))
                    print("Сначала выполните генерацию ключей (режим 1)")
                    continue
                if not os.path.exists(settings['private_key']):
                    print("Ошибка: закрытый ключ не найден: {}".format(settings['private_key']))
                    continue
                if not os.path.exists(settings['input_file']):
                    print("Ошибка: исходный файл не найден: {}".format(settings['input_file']))
                    continue
                
                HybridCryptoSystem.encrypt_file(
                    settings['input_file'],
                    settings['encrypted_file'],
                    settings['encrypted_sym_key'],
                    settings['private_key']
                )
                
            case '3':
                if not os.path.exists(settings['encrypted_file']):
                    print("Ошибка: зашифрованный файл не найден: {}".format(settings['encrypted_file']))
                    continue
                if not os.path.exists(settings['encrypted_sym_key']):
                    print("Ошибка: зашифрованный ключ не найден: {}".format(settings['encrypted_sym_key']))
                    continue
                if not os.path.exists(settings['private_key']):
                    print("Ошибка: закрытый ключ не найден: {}".format(settings['private_key']))
                    continue
                    
                HybridCryptoSystem.decrypt_file(
                    settings['encrypted_file'],
                    settings['decrypted_file'],
                    settings['encrypted_sym_key'],
                    settings['private_key']
                )
                
            case '4':
                settings = None
                settings = load_settings(settings_file)
                if settings:
                    print("\nТекущие настройки:")
                    for key, value in settings.items():
                        new_value = input("  {} [{}]: ".format(key, value)).strip()
                        if new_value:
                            settings[key] = new_value
                    save_settings(settings_file, settings)
                    print("Настройки обновлены")
                else:
                    print("Ошибка при загрузке настроек")
                    
            case '5':
                print("\nДо свидания!")
                break
            
            case _:
                print("Неверный выбор. Попробуйте снова.")


def main():
    """Главная функция с аргументами командной строки.
    
    Принимает: аргументы из командной строки
    Возвращает: None
    """
    parser = argparse.ArgumentParser(description="Гибридная криптосистема (Camellia + RSA)")
    
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-gen','--generation', action='store_true', help='Запускает режим генерации ключей')
    group.add_argument('-enc','--encryption', action='store_true', help='Запускает режим шифрования')
    group.add_argument('-dec','--decryption', action='store_true', help='Запускает режим дешифрования')
    group.add_argument('-i','--interactive', action='store_true', help='Интерактивный режим')
    
    parser.add_argument('--public-key', type=str, help='Путь для сохранения открытого ключа RSA')
    parser.add_argument('--private-key', type=str, help='Путь для сохранения закрытого ключа RSA')
    parser.add_argument('--enc-sym-key', type=str, help='Путь для сохранения зашифрованного симметричного ключа')
    parser.add_argument('--key-size', type=int, choices=[128, 192, 256], default=256, help='Длина ключа Camellia')
    
    parser.add_argument('--input', type=str, help='Путь к входному файлу')
    parser.add_argument('--output', type=str, help='Путь к выходному файлу')
    
    args = parser.parse_args()
    
    if args.interactive or (not any([args.generation, args.encryption, args.decryption])):
        interactive_mode()
        return
    
    if args.generation:
        if not all([args.public_key, args.private_key, args.enc_sym_key]):
            print("Ошибка: для режима генерации укажите --public-key, --private-key и --enc-sym-key")
            return
        
        HybridCryptoSystem.generate_keys(
            args.public_key,
            args.private_key,
            args.enc_sym_key,
            args.key_size
        )
    
    elif args.encryption:
        if not all([args.input, args.output, args.enc_sym_key, args.private_key]):
            print("Ошибка: для режима шифрования укажите --input, --output, --enc-sym-key и --private-key")
            return
        
        if not os.path.exists(args.input):
            print("Ошибка: входной файл не найден: {}".format(args.input))
            return
        
        HybridCryptoSystem.encrypt_file(
            args.input,
            args.output,
            args.enc_sym_key,
            args.private_key
        )
    
    elif args.decryption:
        if not all([args.input, args.output, args.enc_sym_key, args.private_key]):
            print("Ошибка: для режима дешифрования укажите --input, --output, --enc-sym-key и --private-key")
            return
        
        if not os.path.exists(args.input):
            print("Ошибка: входной файл не найден: {}".format(args.input))
            return
        
        HybridCryptoSystem.decrypt_file(
            args.input,
            args.output,
            args.enc_sym_key,
            args.private_key
        )


if __name__ == "__main__":
    main()