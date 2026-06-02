from symmetric import CamelliaCipher
from load_and_save_data import load_json, save_json, file_exists
from load_and_save_data import save_pem_public_key, save_pem_private_key
from load_and_save_data import load_pem_private_key


class HybridCrypto:
    """Гибридная криптосистема Camellia + RSA."""
    
    def __init__(self, config_path='config.json'):
        """Инициализация гибридной системы.
        
        Аргументы:
            config_path: путь к файлу конфигурации
        """
        self.config = load_json(config_path)
        self.block_size = self.config['camellia_block_size']
        self.rsa_key_size = self.config['rsa_key_size']
    
    def generate_keys(self, public_key_path, private_key_path, encrypted_sym_key_path, sym_key_size=256):
        """Сгенерировать все ключи гибридной системы."""
        try:
            print("\n=== РЕЖИМ ГЕНЕРАЦИИ КЛЮЧЕЙ ===")
            
            print(f"1.1. Генерация ключа Camellia (длина {sym_key_size} бит)...")
            symmetric_key = CamelliaCipher.generate_key(sym_key_size)
            print(f"     Симметричный ключ сгенерирован: {symmetric_key.hex()[:16]}...")
            
            print("1.2. Генерация пары ключей RSA (2048 бит)...")
            from cryptography.hazmat.primitives.asymmetric import rsa
            private_key = rsa.generate_private_key(
                public_exponent=self.config['rsa_public_exponent'],
                key_size=self.rsa_key_size
            )
            public_key = private_key.public_key()
            print("     Пара ключей RSA успешно сгенерирована")
            
            print("1.3. Сохранение ключей RSA...")
            # ИСПРАВЛЕНО:直接用函数 из load_and_save_data
            save_pem_public_key(public_key, public_key_path)
            print(f"     Открытый ключ сохранен: {public_key_path}")
            
            save_pem_private_key(private_key, private_key_path)
            print(f"     Закрытый ключ сохранен: {private_key_path}")
            
            print("1.4. Шифрование симметричного ключа открытым ключом RSA...")
            # ИСПРАВЛЕНО: шифруем напрямую
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
                'key_size': sym_key_size
            }
            
            save_json(key_data, encrypted_sym_key_path, indent=self.config['encoding']['json_indent'])
            print(f"     Зашифрованный симметричный ключ сохранен: {encrypted_sym_key_path}")
            
            print("\nГенерация ключей успешно завершена!")
            return True
            
        except Exception as e:
            print(f"Ошибка при генерации ключей: {e}")
            return False
    
    def _load_symmetric_key(self, encrypted_sym_key_path, private_key_path):
        """Загрузить и расшифровать симметричный ключ."""
        key_data = load_json(encrypted_sym_key_path)
        
        encrypted_key = bytes.fromhex(key_data['encrypted_key'])
        key_size = key_data['key_size']
        
        # ИСПРАВЛЕНО:直接用函数
        private_key = load_pem_private_key(private_key_path)
        
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        symmetric_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return symmetric_key, key_size
    
    def encrypt_file(self, input_file_path, output_file_path, encrypted_sym_key_path, private_key_path):
        """Зашифровать файл гибридной системой."""
        try:
            print("\n=== РЕЖИМ ШИФРОВАНИЯ ===")
            
            print("2.1. Расшифровка симметричного ключа...")
            symmetric_key, key_size = self._load_symmetric_key(encrypted_sym_key_path, private_key_path)
            print(f"     Симметричный ключ (Camellia-{key_size}) загружен и расшифрован")
            
            print(f"2.2. Шифрование файла: {input_file_path}")
            
            if not file_exists(input_file_path):
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
        """Расшифровать файл гибридной системой."""
        try:
            print("\n=== РЕЖИМ ДЕШИФРОВАНИЯ ===")
            
            print("3.1. Расшифровка симметричного ключа...")
            symmetric_key, key_size = self._load_symmetric_key(encrypted_sym_key_path, private_key_path)
            print(f"     Симметричный ключ (Camellia-{key_size}) загружен и расшифрован")
            
            print(f"3.2. Дешифрование файла: {encrypted_file_path}")
            
            if not file_exists(encrypted_file_path):
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