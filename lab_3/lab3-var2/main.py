import argparse
import json
import os

from hybrid import HybridCrypto


class Settings:
    """Класс для работы с настройками приложения.
    
    Отвечает за:
    - Загрузку и сохранение настроек в JSON файл
    - Валидацию и обработку ошибок
    - Интерактивное редактирование настроек
    """
    
    SETTINGS_FILE = 'settings.json'
    
    def __init__(self):
        """Инициализация и загрузка настроек."""
        self.settings = self._load()
    
    def _load(self):
        """Загрузить настройки из файла.
        
        Возвращает:
            dict: словарь с настройками или пустой словарь при ошибке
        """
        try:
            if os.path.exists(self.SETTINGS_FILE):
                with open(self.SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return {}
        except json.JSONDecodeError:
            print(f"Ошибка: неверный формат JSON в файле {self.SETTINGS_FILE}")
            return {}
        except Exception as e:
            print(f"Ошибка при загрузке настроек: {e}")
            return {}
    
    def save(self):
        """Сохранить настройки в файл."""
        try:
            with open(self.SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=4, ensure_ascii=False)
            print(f"Настройки сохранены в {self.SETTINGS_FILE}")
        except Exception as e:
            print(f"Ошибка при сохранении настроек: {e}")
    
    def get(self, key, default=None):
        """Получить значение настройки.
        
        Аргументы:
            key: ключ настройки
            default: значение по умолчанию
        
        Возвращает:
            значение настройки или default
        """
        return self.settings.get(key, default)
    
    def set(self, key, value):
        """Установить значение настройки.
        
        Аргументы:
            key: ключ настройки
            value: значение
        """
        self.settings[key] = value
    
    def update_from_input(self):
        """Обновить настройки из пользовательского ввода."""
        print("\nВведите пути к файлам (можно оставить пустым для значения по умолчанию):")
        
        defaults = {
            'public_key': 'public.pem',
            'private_key': 'private.pem',
            'encrypted_sym_key': 'sym_key.enc',
            'input_file': 'input.txt',
            'encrypted_file': 'encrypted.bin',
            'decrypted_file': 'decrypted.txt'
        }
        
        for key, default in defaults.items():
            value = input(f"{key} [{default}]: ").strip()
            self.settings[key] = value if value else default
        
        self.save()
    
    def display(self):
        """Отобразить текущие настройки."""
        print("\nТекущие настройки:")
        for key, value in self.settings.items():
            print(f"  {key}: {value}")
    
    def interactive_edit(self):
        """Интерактивное редактирование настроек."""
        print("\nТекущие настройки:")
        for key, value in self.settings.items():
            new_value = input(f"  {key} [{value}]: ").strip()
            if new_value:
                self.settings[key] = new_value
        self.save()
        print("Настройки обновлены")


def interactive_mode():
    """Интерактивный режим работы с меню.
    
    Позволяет пользователю последовательно:
    1. Сгенерировать ключи
    2. Зашифровать файл
    3. Расшифровать файл
    4. Изменить настройки
    5. Выйти из программы
    """
    print("\n" + "="*60)
    print("ГИБРИДНАЯ КРИПТОСИСТЕМА (Camellia + RSA)")
    print("="*60)
    
    settings = Settings()
    
    if not settings.settings:
        settings.update_from_input()
    else:
        settings.display()
        use_saved = input("\nИспользовать сохраненные настройки? (y/n): ").lower()
        if use_saved != 'y':
            settings.update_from_input()
    
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
                    settings.get('public_key'),
                    settings.get('private_key'),
                    settings.get('encrypted_sym_key'),
                    key_size
                )
                
            case '2':
                crypto.encrypt_file(
                    settings.get('input_file'),
                    settings.get('encrypted_file'),
                    settings.get('encrypted_sym_key'),
                    settings.get('private_key')
                )
                
            case '3':
                crypto.decrypt_file(
                    settings.get('encrypted_file'),
                    settings.get('decrypted_file'),
                    settings.get('encrypted_sym_key'),
                    settings.get('private_key')
                )
                
            case '4':
                settings.interactive_edit()
                    
            case '5':
                print("\nДо свидания!")
                break
            
            case _:
                print("Неверный выбор. Попробуйте снова.")


def main():
    """Главная функция с аргументами командной строки."""
    parser = argparse.ArgumentParser(
        description="Гибридная криптосистема (Camellia + RSA)",
        epilog="Примеры:\n  python main.py -i\n  python main.py -gen --public-key pub.pem --private-key priv.pem --enc-sym-key key.enc"
    )
    
    parser.add_argument('-gen', '--generation', action='store_true', help='Режим генерации ключей')
    parser.add_argument('-enc', '--encryption', action='store_true', help='Режим шифрования')
    parser.add_argument('-dec', '--decryption', action='store_true', help='Режим дешифрования')
    parser.add_argument('-i', '--interactive', action='store_true', help='Интерактивный режим')
    
    parser.add_argument('--public-key', type=str, help='Путь для сохранения открытого ключа RSA')
    parser.add_argument('--private-key', type=str, help='Путь для сохранения закрытого ключа RSA')
    parser.add_argument('--enc-sym-key', type=str, help='Путь для сохранения зашифрованного ключа')
    parser.add_argument('--key-size', type=int, choices=[128, 192, 256], default=256, help='Длина ключа Camellia')
    parser.add_argument('--input', type=str, help='Путь к входному файлу')
    parser.add_argument('--output', type=str, help='Путь к выходному файлу')
    
    args = parser.parse_args()
    
    crypto = HybridCrypto()
    
    # Определяем режим работы
    if args.interactive:
        mode = 'interactive'
    elif args.generation:
        mode = 'generation'
    elif args.encryption:
        mode = 'encryption'
    elif args.decryption:
        mode = 'decryption'
    else:
        mode = 'interactive'
    
    # Чистый match-case без if
    match mode:
        case 'interactive':
            interactive_mode()
        
        case 'generation':
            if not all([args.public_key, args.private_key, args.enc_sym_key]):
                print("Ошибка: для генерации укажите --public-key, --private-key и --enc-sym-key")
                return
            
            crypto.generate_keys(args.public_key, args.private_key, args.enc_sym_key, args.key_size)
        
        case 'encryption':
            if not all([args.input, args.output, args.enc_sym_key, args.private_key]):
                print("Ошибка: для шифрования укажите --input, --output, --enc-sym-key и --private-key")
                return
            
            if not os.path.exists(args.input):
                print(f"Ошибка: входной файл не найден: {args.input}")
                return
            
            crypto.encrypt_file(args.input, args.output, args.enc_sym_key, args.private_key)
        
        case 'decryption':
            if not all([args.input, args.output, args.enc_sym_key, args.private_key]):
                print("Ошибка: для дешифрования укажите --input, --output, --enc-sym-key и --private-key")
                return
            
            if not os.path.exists(args.input):
                print(f"Ошибка: входной файл не найден: {args.input}")
                return
            
            crypto.decrypt_file(args.input, args.output, args.enc_sym_key, args.private_key)
        
        case _:
            print("Неизвестный режим работы")


if __name__ == "__main__":
    main()