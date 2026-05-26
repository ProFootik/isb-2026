import json
import os

from symmetric import CamelliaCipher
from asymmetric import RSACipher


class HybridCrypto:
    """Гибридная криптосистема Camellia + RSA.
    
    Объединяет скорость симметричного шифрования и безопасную передачу ключа.
    Данные шифруются Camellia, ключ Camellia шифруется RSA.
    """
    
    def __init__(self, config_path='config.json'):
        """Инициализация гибридной системы.
        
        Принимает: config_path - путь к файлу конфигурации
        Возвращает: None
        """
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        self.block_size = self.config['camellia_block_size']
    
    def generate_keys(self, public_key_path, private_key_path, encrypted_sym_key_path, sym_key_size=256):
        """Генерация ключей гибридной системы (режим 1).
        
        Принимает:
            public_key_path: путь для сохранения открытого ключа RSA
            private_key_path: путь для сохранения закрытого ключа RSA
            encrypted_sym_key_path: путь для сохранения зашифрованного ключа Camellia
            sym_key_size: длина ключа Camellia в битах (128, 192 или 256)
        Возвращает: True при успехе, False при ошибке
        """
        try:
            print("\n=== РЕЖИМ ГЕНЕРАЦИИ КЛЮЧЕЙ ===")
            
            print(f"1.1. Генерация ключа Camellia (длина {sym_key_size} бит)...")
            symmetric_key = CamelliaCipher.generate_key(sym_key_size)
            print(f"     Симметричный ключ сгенерирован: {symmetric_key.hex()[:16]}...")
            
            print("1.2. Генерация пары ключей RSA (2048 бит)...")
            rsa_cipher = RSACipher(self.config['rsa_key_size'])
            private_key, public_key = rsa_cipher.generate_keys()
            print("     Пара ключей RSA успешно сгенерирована")
            
            print("1.3. Сохранение ключей RSA...")
            rsa_cipher.save_public_key(public_key_path)
            print(f"     Открытый ключ сохранен: {public_key_path}")
            
            rsa_cipher.save_private_key(private_key_path)
            print(f"     Закрытый ключ сохранен: {private_key_path}")
            
            print("1.4. Шифрование симметричного ключа открытым ключом RSA...")
            encrypted_sym_key = RSACipher.encrypt(public_key, symmetric_key)
            
            key_data = {
                'encrypted_key': encrypted_sym_key.hex(),
                'key_size': sym_key_size
            }
            
            with open(encrypted_sym_key_path, 'w') as f:
                json.dump(key_data, f, indent=self.config['encoding']['json_indent'])
            print(f"     Зашифрованный симметричный ключ сохранен: {encrypted_sym_key_path}")
            
            print("\nГенерация ключей успешно завершена!")
            return True
            
        except Exception as e:
            print(f"Ошибка при генерации ключей: {e}")
            return False
    
    def _load_symmetric_key(self, encrypted_sym_key_path, private_key_path):
        """Загрузка и расшифровка симметричного ключа (внутренний метод).
        
        Принимает:
            encrypted_sym_key_path: путь к зашифрованному ключу Camellia
            private_key_path: путь к закрытому ключу RSA
        Возвращает: (symmetric_key, key_size) - кортеж из ключа и его длины в битах
        """
        with open(encrypted_sym_key_path, 'r') as f:
            key_data = json.load(f)
        
        encrypted_key = bytes.fromhex(key_data['encrypted_key'])
        key_size = key_data['key_size']
        
        private_key = RSACipher.load_private_key(private_key_path)
        symmetric_key = RSACipher.decrypt(private_key, encrypted_key)
        
        return symmetric_key, key_size
    
    def encrypt_file(self, input_file_path, output_file_path, encrypted_sym_key_path, private_key_path):
        """Шифрование файла гибридной системой (режим 2).
        
        Принимает:
            input_file_path: путь к исходному текстовому файлу
            output_file_path: путь для сохранения зашифрованного файла
            encrypted_sym_key_path: путь к зашифрованному ключу Camellia
            private_key_path: путь к закрытому ключу RSA
        Возвращает: True при успехе, False при ошибке
        """
        try:
            print("\n=== РЕЖИМ ШИФРОВАНИЯ ===")
            
            print("2.1. Расшифровка симметричного ключа...")
            symmetric_key, key_size = self._load_symmetric_key(encrypted_sym_key_path, private_key_path)
            print(f"     Симметричный ключ (Camellia-{key_size}) загружен и расшифрован")
            
            print(f"2.2. Шифрование файла: {input_file_path}")
            
            if not os.path.exists(input_file_path):
                print(f"Ошибка: исходный файл не найден: {input_file_path}")
                return False
            
            with open(input_file_path, 'rb') as f:
                plaintext = f.read()
            
            print(f"     Размер исходного файла: {len(plaintext)} байт")
            
            camellia = CamelliaCipher(symmetric_key)
            iv, ciphertext = camellia.encrypt(plaintext)
            
            with open(output_file_path, 'wb') as f:
                f.write(iv + ciphertext)
            
            print(f"     Размер зашифрованного файла: {len(iv) + len(ciphertext)} байт")
            print(f"     Зашифрованный файл сохранен: {output_file_path}")
            
            print("\nШифрование успешно завершено!")
            return True
            
        except Exception as e:
            print(f"Ошибка при шифровании: {e}")
            return False
    
    def decrypt_file(self, encrypted_file_path, output_file_path, encrypted_sym_key_path, private_key_path):
        """Дешифрование файла гибридной системой (режим 3).
        
        Принимает:
            encrypted_file_path: путь к зашифрованному файлу
            output_file_path: путь для сохранения расшифрованного файла
            encrypted_sym_key_path: путь к зашифрованному ключу Camellia
            private_key_path: путь к закрытому ключу RSA
        Возвращает: True при успехе, False при ошибке
        """
        try:
            print("\n=== РЕЖИМ ДЕШИФРОВАНИЯ ===")
            
            print("3.1. Расшифровка симметричного ключа...")
            symmetric_key, key_size = self._load_symmetric_key(encrypted_sym_key_path, private_key_path)
            print(f"     Симметричный ключ (Camellia-{key_size}) загружен и расшифрован")
            
            print(f"3.2. Дешифрование файла: {encrypted_file_path}")
            
            if not os.path.exists(encrypted_file_path):
                print(f"Ошибка: зашифрованный файл не найден: {encrypted_file_path}")
                return False
            
            with open(encrypted_file_path, 'rb') as f:
                data = f.read()
            
            iv = data[:self.block_size]
            ciphertext = data[self.block_size:]
            
            print(f"     Размер зашифрованного файла: {len(data)} байт")
            
            camellia = CamelliaCipher(symmetric_key)
            plaintext = camellia.decrypt(ciphertext, iv)
            
            with open(output_file_path, 'wb') as f:
                f.write(plaintext)
            
            print(f"     Размер расшифрованного файла: {len(plaintext)} байт")
            print(f"     Расшифрованный файл сохранен: {output_file_path}")
            
            print("\nДешифрование успешно завершено!")
            return True
            
        except Exception as e:
            print(f"Ошибка при дешифровании: {e}")
            return False