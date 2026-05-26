import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class CamelliaCipher:
    """Реализация симметричного шифрования алгоритмом Camellia."""
    
    def __init__(self, key, config_path='config.json'):
        """Инициализация шифра Camellia.
        
        Принимает:
            key: ключ шифрования (16/24/32 байта)
            config_path: путь к файлу конфигурации
        """
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
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
        """Шифрование данных.
        
        Принимает: plaintext - данные, iv - вектор инициализации (опционально)
        Возвращает: (iv, ciphertext)
        """
        if iv is None:
            iv = os.urandom(self.block_size)
        
        cipher = Cipher(algorithms.Camellia(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        padder = padding.ANSIX923(self.block_size_bits).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv, ciphertext
    
    def decrypt(self, ciphertext, iv):
        """Дешифрование данных.
        
        Принимает: ciphertext - зашифрованные данные, iv - вектор инициализации
        Возвращает: plaintext
        """
        cipher = Cipher(algorithms.Camellia(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.ANSIX923(self.block_size_bits).unpadder()
        plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return plaintext
    
    @staticmethod
    def generate_key(key_size_bits=256, config_path='config.json'):
        """Генерация случайного ключа Camellia.
        
        Принимает: key_size_bits - длина ключа (128/192/256), config_path - путь к конфигу
        Возвращает: bytes - сгенерированный ключ
        """
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        key_sizes = config['camellia_key_sizes']
        
        if str(key_size_bits) not in key_sizes:
            raise ValueError(f"Длина ключа должна быть {list(key_sizes.keys())} бит, получено {key_size_bits}")
        
        key_size_bytes = key_sizes[str(key_size_bits)]
        return os.urandom(key_size_bytes)