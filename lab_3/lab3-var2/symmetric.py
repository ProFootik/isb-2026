import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class CamelliaCipher:
    """Реализация симметричного шифрования алгоритмом Camellia.
    
    Поддерживаемые длины ключа: 128, 192, 256 бит.
    Режим шифрования: CBC.
    Паддинг: ANSI X9.23.
    """
    
    def __init__(self, key, config_path='config.json'):
        """Инициализация шифра Camellia.
        
        Аргументы:
            key: ключ шифрования (16, 24 или 32 байта)
            config_path: путь к файлу конфигурации
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            print(f"Ошибка: файл конфигурации {config_path} не найден")
            raise
        except json.JSONDecodeError:
            print(f"Ошибка: файл {config_path} содержит некорректный JSON")
            raise
        
        self.block_size = self.config['camellia_block_size']
        self.block_size_bits = self.config['camellia_block_size_bits']
        self.key_sizes = self.config['camellia_key_sizes']
        
        key_len = len(key)
        valid_sizes = list(self.key_sizes.values())
        
        if key_len not in valid_sizes:
            raise ValueError(f"Длина ключа должна быть {valid_sizes} байт, получено {key_len}")
        
        self.key = key
        size_map = {v: int(k) for k, v in self.key_sizes.items()}
        self.key_size_bits = size_map[key_len]
    
    def encrypt(self, plaintext, iv=None):
        """Зашифровать данные в режиме CBC.
        
        Аргументы:
            plaintext: исходные данные (байты)
            iv: вектор инициализации (16 байт, опционально)
        
        Возвращает:
            tuple: (iv, ciphertext) - вектор инициализации и зашифрованные данные
        """
        try:
            if iv is None:
                iv = os.urandom(self.block_size)
            
            cipher = Cipher(algorithms.Camellia(self.key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            padder = padding.ANSIX923(self.block_size_bits).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            return iv, ciphertext
        except Exception as e:
            print(f"Ошибка при шифровании Camellia: {e}")
            raise
    
    def decrypt(self, ciphertext, iv):
        """Расшифровать данные в режиме CBC.
        
        Аргументы:
            ciphertext: зашифрованные данные (байты)
            iv: вектор инициализации (16 байт)
        
        Возвращает:
            bytes: расшифрованные данные
        """
        try:
            cipher = Cipher(algorithms.Camellia(self.key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = padding.ANSIX923(self.block_size_bits).unpadder()
            plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
            
            return plaintext
        except Exception as e:
            print(f"Ошибка при дешифровании Camellia: {e}")
            raise
    
    @staticmethod
    def generate_key(key_size_bits=256, config_path='config.json'):
        """Сгенерировать случайный ключ Camellia.
        
        Аргументы:
            key_size_bits: длина ключа в битах (128, 192 или 256)
            config_path: путь к файлу конфигурации
        
        Возвращает:
            bytes: сгенерированный ключ
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except FileNotFoundError:
            print(f"Ошибка: файл конфигурации {config_path} не найден")
            raise
        except json.JSONDecodeError:
            print(f"Ошибка: файл {config_path} содержит некорректный JSON")
            raise
        
        key_sizes = config['camellia_key_sizes']
        
        if str(key_size_bits) not in key_sizes:
            raise ValueError(f"Длина ключа должна быть {list(key_sizes.keys())} бит, получено {key_size_bits}")
        
        key_size_bytes = key_sizes[str(key_size_bits)]
        return os.urandom(key_size_bytes)