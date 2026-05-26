import argparse
import json
import os

from hybrid_crypto import HybridCrypto


def load_settings(settings_path='settings.json'):
    """Загрузка настроек из JSON файла.
    
    Принимает: путь к файлу настроек
    Возвращает: словарь с настройками или None
    """
    try:
        if os.path.exists(settings_path):
            with open(settings_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return None
    except json.JSONDecodeError:
        print(f"Ошибка: неверный формат JSON в файле {settings_path}")
        return None
    except Exception as e:
        print(f"Ошибка при загрузке настроек: {e}")
        return None


def save_settings(settings_path, settings):
    """Сохранение настроек в JSON файл.
    
    Принимает: путь к файлу и словарь с настройками
    Возвращает: None
    """
    try:
        with open(settings_path, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=4, ensure_ascii=False)
        print(f"Настройки сохранены в {settings_path}")
    except Exception as e:
        print(f"Ошибка при сохранении настроек: {e}")


def interactive_mode():
    """Интерактивный режим работы с меню.
    
    Принимает: None
    Возвращает: None
    """
    print("\n" + "="*60)
    print("ГИБРИДНАЯ КРИПТОСИСТЕМА (Camellia + RSA)")
    print("="*60)
    
    settings_file = 'settings.json'
    settings = load_settings(settings_file)
    
    if settings:
        print(f"\nНайдены сохраненные настройки в {settings_file}:")
        for key, value in settings.items():
            print(f"  {key}: {value}")
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
    
    crypto = HybridCrypto()
    
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
                
                crypto.generate_keys(
                    settings['public_key'],
                    settings['private_key'],
                    settings['encrypted_sym_key'],
                    key_size
                )
                
            case '2':
                crypto.encrypt_file(
                    settings['input_file'],
                    settings['encrypted_file'],
                    settings['encrypted_sym_key'],
                    settings['private_key']
                )
                
            case '3':
                crypto.decrypt_file(
                    settings['encrypted_file'],
                    settings['decrypted_file'],
                    settings['encrypted_sym_key'],
                    settings['private_key']
                )
                
            case '4':
                settings = load_settings(settings_file)
                if settings:
                    print("\nТекущие настройки:")
                    for key, value in settings.items():
                        new_value = input(f"  {key} [{value}]: ").strip()
                        if new_value:
                            settings[key] = new_value
                    save_settings(settings_file, settings)
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
    group.add_argument('-gen', '--generation', action='store_true', help='Режим генерации ключей')
    group.add_argument('-enc', '--encryption', action='store_true', help='Режим шифрования')
    group.add_argument('-dec', '--decryption', action='store_true', help='Режим дешифрования')
    group.add_argument('-i', '--interactive', action='store_true', help='Интерактивный режим')
    
    parser.add_argument('--public-key', type=str, help='Путь для открытого ключа RSA')
    parser.add_argument('--private-key', type=str, help='Путь для закрытого ключа RSA')
    parser.add_argument('--enc-sym-key', type=str, help='Путь для зашифрованного ключа')
    parser.add_argument('--key-size', type=int, choices=[128, 192, 256], default=256, help='Длина ключа Camellia')
    parser.add_argument('--input', type=str, help='Путь к входному файлу')
    parser.add_argument('--output', type=str, help='Путь к выходному файлу')
    
    args = parser.parse_args()
    
    crypto = HybridCrypto()
    
    match True:
        case _ if args.interactive or (not any([args.generation, args.encryption, args.decryption])):
            interactive_mode()
            
        case _ if args.generation:
            if not all([args.public_key, args.private_key, args.enc_sym_key]):
                print("Ошибка: для генерации укажите --public-key, --private-key и --enc-sym-key")
                return
            
            crypto.generate_keys(args.public_key, args.private_key, args.enc_sym_key, args.key_size)
            
        case _ if args.encryption:
            if not all([args.input, args.output, args.enc_sym_key, args.private_key]):
                print("Ошибка: для шифрования укажите --input, --output, --enc-sym-key и --private-key")
                return
            
            crypto.encrypt_file(args.input, args.output, args.enc_sym_key, args.private_key)
            
        case _ if args.decryption:
            if not all([args.input, args.output, args.enc_sym_key, args.private_key]):
                print("Ошибка: для дешифрования укажите --input, --output, --enc-sym-key и --private-key")
                return
            
            crypto.decrypt_file(args.input, args.output, args.enc_sym_key, args.private_key)


if __name__ == "__main__":
    main()