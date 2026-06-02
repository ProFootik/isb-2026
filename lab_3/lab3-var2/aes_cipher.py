import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from load_and_save_data import load_json


class AESCipher:
    """Реализация симметричного шифрования алгоритмом AES.
    
    Поддерживаемые длины ключа: 128, 192, 256 бит.
    Режим шифрования: CBC.
    Паддинг: ANSI X9.23.
    """
    
    def __init__(self, key, config_path='config.json'):
        """Инициализация шифра AES.
        
        Аргументы:
            key: ключ шифрования (16, 24 или 32 байта)
            config_path: путь к файлу конфигурации
        """
        self.config = load_json(config_path)
        
        self.block_size = self.config['aes_block_size']
        self.block_size_bits = self.config['aes_block_size_bits']
        self.key_sizes = self.config['aes_key_sizes']
        
        key_len = len(key)
        valid_sizes = list(self.key_sizes.values())
        
        if key_len not in valid_sizes:
            raise ValueError(f"Длина ключа AES должна быть {valid_sizes} байт, получено {key_len}")
        
        self.key = key
        size_map = {v: int(k) for k, v in self.key_sizes.items()}
        self.key_size_bits = size_map[key_len]
    
    def encrypt(self, plaintext, iv=None):
        """Зашифровать данные в режиме CBC.
        
        Аргументы:
            plaintext: исходные данные (байты)
            iv: вектор инициализации (16 байт, опционально)
        
        Возвращает:
            tuple: (iv, ciphertext)
        """
        if iv is None:
            iv = os.urandom(self.block_size)
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        padder = padding.ANSIX923(self.block_size_bits).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv, ciphertext
    
    def decrypt(self, ciphertext, iv):
        """Расшифровать данные в режиме CBC.
        
        Аргументы:
            ciphertext: зашифрованные данные (байты)
            iv: вектор инициализации (16 байт)
        
        Возвращает:
            bytes: расшифрованные данные
        """
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.ANSIX923(self.block_size_bits).unpadder()
        plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return plaintext
    
    @staticmethod
    def generate_key(key_size_bits=256, config_path='config.json'):
        """Сгенерировать случайный ключ AES.
        
        Аргументы:
            key_size_bits: длина ключа в битах (128, 192 или 256)
            config_path: путь к файлу конфигурации
        
        Возвращает:
            bytes: сгенерированный ключ
        """
        config = load_json(config_path)
        
        key_sizes = config['aes_key_sizes']
        
        if str(key_size_bits) not in key_sizes:
            raise ValueError(f"Длина ключа AES должна быть {list(key_sizes.keys())} бит, получено {key_size_bits}")
        
        key_size_bytes = key_sizes[str(key_size_bits)]
        return os.urandom(key_size_bytes)