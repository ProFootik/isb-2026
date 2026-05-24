from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os


class CamelliaCipher:
    """Реализация симметричного шифрования алгоритмом Camellia"""
    
    BLOCK_SIZE = 16
    
    KEY_SIZES = {
        128: 16,
        192: 24,
        256: 32
    }
    
    def __init__(self, key):
        """Инициализация шифра Camellia.
        
        Принимает: key - ключ шифрования (16/24/32 байта)
        Возвращает: None
        """

        key_len = len(key)
        if key_len not in [16, 24, 32]:
            raise ValueError("Длина ключа должна быть 16, 24 или 32 байта, получено {}".format(key_len))
        
        self.key = key
        self.key_size_bits = {16: 128, 24: 192, 32: 256}[key_len]
    
    def encrypt(self, plaintext, iv=None):
        """Шифрование данных.
        
        Принимает: plaintext - данные, iv - вектор инициализации (опционально)
        Возвращает: (iv, ciphertext)
        """
        if iv is None:
            iv = os.urandom(self.BLOCK_SIZE)
        
        cipher = Cipher(algorithms.Camellia(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        padder = padding.ANSIX923(self.BLOCK_SIZE * 8).padder()
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
        
        unpadder = padding.ANSIX923(self.BLOCK_SIZE * 8).unpadder()
        plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return plaintext
    
    @staticmethod
    def generate_key(key_size_bits=256):
        """Генерация случайного ключа.
        
        Принимает: key_size_bits - длина ключа (128/192/256)
        Возвращает: bytes - сгенерированный ключ
        """
        if key_size_bits not in CamelliaCipher.KEY_SIZES:
            raise ValueError("Длина ключа должна быть 128, 192 или 256 бит, получено {}".format(key_size_bits))
        
        key_size_bytes = CamelliaCipher.KEY_SIZES[key_size_bits]
        return os.urandom(key_size_bytes)