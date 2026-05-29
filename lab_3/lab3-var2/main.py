import argparse

from hybrid import HybridCrypto
from load_and_save import load_json, save_json, check_file_exists


def load_settings():
    """Загрузить настройки из settings.json."""
    settings = load_json('settings.json')
    if settings is None:
        return {}
    return settings


def save_settings(settings):
    """Сохранить настройки в settings.json."""
    save_json(settings, 'settings.json')


def interactive_mode():
    """Интерактивный режим с меню."""
    crypto = HybridCrypto()
    settings = load_settings()
    
    print("\n" + "="*50)
    print("ГИБРИДНАЯ КРИПТОСИСТЕМА")
    print("Camellia + RSA")
    print("="*50)
    
    # Если нет настроек, запрашиваем
    if not settings:
        print("\nВведите пути к файлам (Enter - значение по умолчанию):")
        settings['public_key'] = input("Открытый ключ RSA [public.pem]: ") or "public.pem"
        settings['private_key'] = input("Закрытый ключ RSA [private.pem]: ") or "private.pem"
        settings['encrypted_sym_key'] = input("Зашифрованный ключ [sym_key.enc]: ") or "sym_key.enc"
        settings['input_file'] = input("Исходный файл [input.txt]: ") or "input.txt"
        settings['encrypted_file'] = input("Зашифрованный файл [encrypted.bin]: ") or "encrypted.bin"
        settings['decrypted_file'] = input("Расшифрованный файл [decrypted.txt]: ") or "decrypted.txt"
        save_settings(settings)
    
    while True:
        print("\n" + "-"*30)
        print("1. Генерация ключей")
        print("2. Шифрование файла")
        print("3. Дешифрование файла")
        print("4. Выход")
        
        choice = input("\nВыберите пункт: ")
        
        match choice:
            case "1":
                print("\nДоступные длины: 128, 192, 256")
                try:
                    key_size = int(input("Введите длину ключа [256]: ") or "256")
                    if key_size not in [128, 192, 256]:
                        print("Ошибка! Длина должна быть 128, 192 или 256")
                        continue
                except ValueError:
                    print("Ошибка! Введите число")
                    continue
                
                crypto.generate_keys(
                    settings['public_key'],
                    settings['private_key'],
                    settings['encrypted_sym_key'],
                    key_size
                )
            
            case "2":
                if not check_file_exists(settings['encrypted_sym_key']):
                    print("Ошибка! Сначала сгенерируйте ключи (пункт 1)")
                    continue
                if not check_file_exists(settings['private_key']):
                    print("Ошибка! Закрытый ключ не найден")
                    continue
                if not check_file_exists(settings['input_file']):
                    print("Ошибка! Файл {} не найден".format(settings['input_file']))
                    continue
                
                crypto.encrypt_file(
                    settings['input_file'],
                    settings['encrypted_file'],
                    settings['encrypted_sym_key'],
                    settings['private_key']
                )
            
            case "3":
                if not check_file_exists(settings['encrypted_file']):
                    print("Ошибка! Зашифрованный файл не найден")
                    continue
                if not check_file_exists(settings['encrypted_sym_key']):
                    print("Ошибка! Зашифрованный ключ не найден")
                    continue
                if not check_file_exists(settings['private_key']):
                    print("Ошибка! Закрытый ключ не найден")
                    continue
                
                crypto.decrypt_file(
                    settings['encrypted_file'],
                    settings['decrypted_file'],
                    settings['encrypted_sym_key'],
                    settings['private_key']
                )
            
            case "4":
                print("\nДо свидания!")
                break
            
            case _:
                print("Неверный выбор!")


def main():
    """Главная функция с аргументами командной строки."""
    parser = argparse.ArgumentParser(description="Гибридная криптосистема")
    
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-gen', '--generation', action='store_true', help='Генерация ключей')
    group.add_argument('-enc', '--encryption', action='store_true', help='Шифрование')
    group.add_argument('-dec', '--decryption', action='store_true', help='Дешифрование')
    group.add_argument('-i', '--interactive', action='store_true', help='Интерактивный режим')
    
    parser.add_argument('--public-key', help='Открытый ключ RSA')
    parser.add_argument('--private-key', help='Закрытый ключ RSA')
    parser.add_argument('--enc-sym-key', help='Зашифрованный ключ Camellia')
    parser.add_argument('--key-size', type=int, default=256, help='Длина ключа (128/192/256)')
    parser.add_argument('--input', help='Входной файл')
    parser.add_argument('--output', help='Выходной файл')
    
    args = parser.parse_args()
    
    crypto = HybridCrypto()
    
    match True:
        case _ if args.interactive or (not any([args.generation, args.encryption, args.decryption])):
            interactive_mode()
        
        case _ if args.generation:
            if not all([args.public_key, args.private_key, args.enc_sym_key]):
                print("Ошибка! Укажите --public-key, --private-key и --enc-sym-key")
                return
            crypto.generate_keys(args.public_key, args.private_key, args.enc_sym_key, args.key_size)
        
        case _ if args.encryption:
            if not all([args.input, args.output, args.enc_sym_key, args.private_key]):
                print("Ошибка! Укажите --input, --output, --enc-sym-key и --private-key")
                return
            crypto.encrypt_file(args.input, args.output, args.enc_sym_key, args.private_key)
        
        case _ if args.decryption:
            if not all([args.input, args.output, args.enc_sym_key, args.private_key]):
                print("Ошибка! Укажите --input, --output, --enc-sym-key и --private-key")
                return
            crypto.decrypt_file(args.input, args.output, args.enc_sym_key, args.private_key)


if __name__ == "__main__":
    main()