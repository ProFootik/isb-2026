from symmetric import CamelliaCipher, generate_camellia_key
from asymmetric import RSACipher
from load_and_save import load_json, save_json, load_bytes, save_bytes, check_file_exists


class HybridCrypto:
    """Гибридная криптосистема: Camellia для данных, RSA для ключа."""
    
    def __init__(self, config_path='config.json'):
        """Загрузка конфигурации."""
        self.config = load_json(config_path)
        self.block_size = self.config['camellia_block_size']
    
    def generate_keys(self, public_path, private_path, enc_sym_path, key_size=256):
        """Генерация всех ключей.
        
        Принимает:
            public_path - путь для открытого ключа RSA
            private_path - путь для закрытого ключа RSA
            enc_sym_path - путь для зашифрованного ключа Camellia
            key_size - длина ключа Camellia (128/192/256)
        Возвращает: True при успехе, False при ошибке
        """
        try:
            print("\n=== ГЕНЕРАЦИЯ КЛЮЧЕЙ ===")
            
            print("1. Генерация ключа Camellia-{}...".format(key_size))
            sym_key = generate_camellia_key(key_size)
            print("   Ключ: {}...".format(sym_key.hex()[:16]))
            
            print("2. Генерация ключей RSA...")
            rsa = RSACipher(self.config['rsa_key_size'])
            private_key, public_key = rsa.generate_keys()
            print("   Ключи RSA сгенерированы")
            
            print("3. Сохранение ключей RSA...")
            rsa.save_public_key(public_path)
            rsa.save_private_key(private_path)
            print("   Открытый ключ: {}".format(public_path))
            print("   Закрытый ключ: {}".format(private_path))
            
            print("4. Шифрование ключа Camellia...")
            encrypted = RSACipher.encrypt(public_key, sym_key)
            
            key_data = {
                'encrypted_key': encrypted.hex(),
                'key_size': key_size
            }
            save_json(key_data, enc_sym_path)
            
            return True
            
        except Exception as e:
            print("Ошибка: {}".format(e))
            return False
    
    def encrypt_file(self, input_path, output_path, enc_sym_path, private_path):
        """Шифрование файла.
        
        Принимает:
            input_path - исходный файл
            output_path - зашифрованный файл
            enc_sym_path - зашифрованный ключ Camellia
            private_path - закрытый ключ RSA
        Возвращает: True при успехе, False при ошибке
        """
        try:
            print("\n=== ШИФРОВАНИЕ ===")
            
            print("1. Получение ключа Camellia...")
            sym_key, key_size = self._get_sym_key(enc_sym_path, private_path)
            print("   Ключ Camellia-{} получен".format(key_size))
            
            print("2. Чтение файла: {}".format(input_path))
            if not check_file_exists(input_path):
                print("Ошибка: файл не найден")
                return False
            
            plaintext = load_bytes(input_path)
            print("   Размер: {} байт".format(len(plaintext)))
            
            print("3. Шифрование Camellia...")
            camellia = CamelliaCipher(sym_key)
            iv, ciphertext = camellia.encrypt(plaintext)
            
            print("4. Сохранение результата...")
            save_bytes(iv + ciphertext, output_path)
            
            return True
            
        except Exception as e:
            print("Ошибка: {}".format(e))
            return False
    
    def decrypt_file(self, input_path, output_path, enc_sym_path, private_path):
        """Дешифрование файла.
        
        Принимает:
            input_path - зашифрованный файл
            output_path - расшифрованный файл
            enc_sym_path - зашифрованный ключ Camellia
            private_path - закрытый ключ RSA
        Возвращает: True при успехе, False при ошибке
        """
        try:
            print("\n=== ДЕШИФРОВАНИЕ ===")
            
            print("1. Получение ключа Camellia...")
            sym_key, key_size = self._get_sym_key(enc_sym_path, private_path)
            print("   Ключ Camellia-{} получен".format(key_size))
            
            print("2. Чтение файла: {}".format(input_path))
            if not check_file_exists(input_path):
                print("Ошибка: файл не найден")
                return False
            
            data = load_bytes(input_path)
            iv = data[:self.block_size]
            ciphertext = data[self.block_size:]
            print("   Размер: {} байт".format(len(data)))
            
            print("3. Дешифрование Camellia...")
            camellia = CamelliaCipher(sym_key)
            plaintext = camellia.decrypt(ciphertext, iv)
            
            print("4. Сохранение результата...")
            save_bytes(plaintext, output_path)
            
            return True
            
        except Exception as e:
            print("Ошибка: {}".format(e))
            return False
    
    def _get_sym_key(self, enc_sym_path, private_path):
        """Внутренний метод: получить расшифрованный ключ Camellia.
        
        Принимает: путь к зашифрованному ключу, путь к закрытому ключу RSA
        Возвращает: (ключ, размер_ключа)
        """
        key_data = load_json(enc_sym_path)
        if key_data is None:
            raise Exception("Не удалось загрузить зашифрованный ключ")
        
        encrypted_key = bytes.fromhex(key_data['encrypted_key'])
        key_size = key_data['key_size']
        
        private_key = RSACipher.load_private_key(private_path)
        symmetric_key = RSACipher.decrypt(private_key, encrypted_key)
        
        return symmetric_key, key_size