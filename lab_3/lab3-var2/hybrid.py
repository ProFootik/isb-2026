from load_and_save_data import load_json, save_json, file_exists
from load_and_save_data import save_pem_public_key, save_pem_private_key
from load_and_save_data import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class HybridCrypto:
    """Гибридная криптосистема с поддержкой Camellia и AES."""
    
    def __init__(self, config_path='config.json'):
        """Инициализация гибридной системы.
        
        Аргументы:
            config_path: путь к файлу конфигурации
        """
        self.config = load_json(config_path)
        self.rsa_key_size = self.config['rsa_key_size']
        self.available_algorithms = self.config['available_symmetric_algorithms']
    
    def _get_cipher_class(self, algorithm_name):
        """Получить класс шифра по имени алгоритма.
        
        Аргументы:
            algorithm_name: имя алгоритма ('camellia' или 'aes')
        
        Возвращает:
            class: класс шифра (CamelliaCipher или AESCipher)
        """
        match algorithm_name:
            case 'camellia':
                from symmetric import CamelliaCipher
                return CamelliaCipher
            case 'aes':
                from aes_cipher import AESCipher
                return AESCipher
            case _:
                raise ValueError(f"Неизвестный алгоритм: {algorithm_name}")
    
    def generate_keys(self, public_key_path, private_key_path, encrypted_sym_key_path, 
                      sym_key_size=256, algorithm='camellia'):
        """Сгенерировать все ключи гибридной системы.
        
        Аргументы:
            public_key_path: путь для сохранения открытого ключа RSA
            private_key_path: путь для сохранения закрытого ключа RSA
            encrypted_sym_key_path: путь для сохранения зашифрованного ключа
            sym_key_size: длина симметричного ключа в битах (128, 192 или 256)
            algorithm: симметричный алгоритм ('camellia' или 'aes')
        
        Возвращает:
            bool: True при успехе, False при ошибке
        """
        try:
            print("\n=== РЕЖИМ ГЕНЕРАЦИИ КЛЮЧЕЙ ===")
            
            if algorithm not in self.available_algorithms:
                print(f"Ошибка: алгоритм {algorithm} не поддерживается")
                print(f"Доступные алгоритмы: {self.available_algorithms}")
                return False
            
            print(f"1.1. Генерация ключа {algorithm.upper()} (длина {sym_key_size} бит)...")
            CipherClass = self._get_cipher_class(algorithm)
            symmetric_key = CipherClass.generate_key(sym_key_size)
            print(f"     Симметричный ключ сгенерирован: {symmetric_key.hex()[:16]}...")
            
            print("1.2. Генерация пары ключей RSA...")
            from cryptography.hazmat.primitives.asymmetric import rsa
            private_key = rsa.generate_private_key(
                public_exponent=self.config['rsa_public_exponent'],
                key_size=self.rsa_key_size
            )
            public_key = private_key.public_key()
            print("     Пара ключей RSA (2048 бит) успешно сгенерирована")
            
            print("1.3. Сохранение ключей RSA...")
            save_pem_public_key(public_key, public_key_path)
            print(f"     Открытый ключ сохранен: {public_key_path}")
            
            save_pem_private_key(private_key, private_key_path)
            print(f"     Закрытый ключ сохранен: {private_key_path}")
            
            print("1.4. Шифрование симметричного ключа открытым ключом RSA...")
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import hashes
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
                'key_size': sym_key_size,
                'algorithm': algorithm
            }
            
            save_json(key_data, encrypted_sym_key_path, indent=self.config['encoding']['json_indent'])
            print(f"     Зашифрованный симметричный ключ сохранен: {encrypted_sym_key_path}")
            print(f"     Использован алгоритм: {algorithm.upper()}")
            
            print("\nГенерация ключей успешно завершена!")
            return True
            
        except Exception as e:
            print(f"Ошибка при генерации ключей: {e}")
            return False
    
    def _load_symmetric_key(self, encrypted_sym_key_path, private_key_path):
        """Загрузить и расшифровать симметричный ключ.
        
        Аргументы:
            encrypted_sym_key_path: путь к зашифрованному ключу
            private_key_path: путь к закрытому ключу RSA
        
        Возвращает:
            tuple: (symmetric_key, key_size, algorithm)
        """
        key_data = load_json(encrypted_sym_key_path)
        
        encrypted_key = bytes.fromhex(key_data['encrypted_key'])
        key_size = key_data['key_size']
        algorithm = key_data.get('algorithm', 'camellia')
        
        private_key = load_pem_private_key(private_key_path)
        
        symmetric_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return symmetric_key, key_size, algorithm
    
    def _get_block_size(self, algorithm):
        """Получить размер блока для алгоритма.
        
        Аргументы:
            algorithm: имя алгоритма ('camellia' или 'aes')
        
        Возвращает:
            int: размер блока в байтах
        """
        match algorithm:
            case 'camellia':
                return self.config['camellia_block_size']
            case 'aes':
                return self.config['aes_block_size']
            case _:
                return 16
    
    def encrypt_file(self, input_file_path, output_file_path, encrypted_sym_key_path, private_key_path):
        """Зашифровать файл гибридной системой.
        
        Аргументы:
            input_file_path: путь к исходному текстовому файлу
            output_file_path: путь для сохранения зашифрованного файла
            encrypted_sym_key_path: путь к зашифрованному ключу
            private_key_path: путь к закрытому ключу RSA
        
        Возвращает:
            bool: True при успехе, False при ошибке
        """
        try:
            print("\n=== РЕЖИМ ШИФРОВАНИЯ ===")
            
            print("2.1. Расшифровка симметричного ключа...")
            symmetric_key, key_size, algorithm = self._load_symmetric_key(
                encrypted_sym_key_path, private_key_path
            )
            print(f"     Симметричный ключ ({algorithm.upper()}-{key_size}) загружен и расшифрован")
            
            print(f"2.2. Шифрование файла: {input_file_path}")
            
            if not file_exists(input_file_path):
                print(f"Ошибка: исходный файл не найден: {input_file_path}")
                return False
            
            with open(input_file_path, 'rb') as f:
                plaintext = f.read()
            
            print(f"     Размер исходного файла: {len(plaintext)} байт")
            
            CipherClass = self._get_cipher_class(algorithm)
            cipher_obj = CipherClass(symmetric_key)
            iv, ciphertext = cipher_obj.encrypt(plaintext)
            
            with open(output_file_path, 'wb') as f:
                f.write(iv + ciphertext)
            
            print(f"     Размер зашифрованного файла: {len(iv) + len(ciphertext)} байт")
            print(f"     Зашифрованный файл сохранен: {output_file_path}")
            print(f"     Использован алгоритм: {algorithm.upper()}")
            
            print("\nШифрование успешно завершено!")
            return True
            
        except Exception as e:
            print(f"Ошибка при шифровании: {e}")
            return False
    
    def decrypt_file(self, encrypted_file_path, output_file_path, encrypted_sym_key_path, private_key_path):
        """Расшифровать файл гибридной системой.
        
        Аргументы:
            encrypted_file_path: путь к зашифрованному файлу
            output_file_path: путь для сохранения расшифрованного файла
            encrypted_sym_key_path: путь к зашифрованному ключу
            private_key_path: путь к закрытому ключу RSA
        
        Возвращает:
            bool: True при успехе, False при ошибке
        """
        try:
            print("\n=== РЕЖИМ ДЕШИФРОВАНИЯ ===")
            
            print("3.1. Расшифровка симметричного ключа...")
            symmetric_key, key_size, algorithm = self._load_symmetric_key(
                encrypted_sym_key_path, private_key_path
            )
            print(f"     Симметричный ключ ({algorithm.upper()}-{key_size}) загружен и расшифрован")
            
            print(f"3.2. Дешифрование файла: {encrypted_file_path}")
            
            if not file_exists(encrypted_file_path):
                print(f"Ошибка: зашифрованный файл не найден: {encrypted_file_path}")
                return False
            
            with open(encrypted_file_path, 'rb') as f:
                data = f.read()
            
            block_size = self._get_block_size(algorithm)
            iv = data[:block_size]
            ciphertext = data[block_size:]
            
            print(f"     Размер зашифрованного файла: {len(data)} байт")
            
            CipherClass = self._get_cipher_class(algorithm)
            cipher_obj = CipherClass(symmetric_key)
            plaintext = cipher_obj.decrypt(ciphertext, iv)
            
            with open(output_file_path, 'wb') as f:
                f.write(plaintext)
            
            print(f"     Размер расшифрованного файла: {len(plaintext)} байт")
            print(f"     Расшифрованный файл сохранен: {output_file_path}")
            print(f"     Использован алгоритм: {algorithm.upper()}")
            
            print("\nДешифрование успешно завершено!")
            return True
            
        except Exception as e:
            print(f"Ошибка при дешифровании: {e}")
            return False