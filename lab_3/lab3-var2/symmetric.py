import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class CamelliaCipher:
    """Класс для шифрования алгоритмом Camellia (вариант 5)."""
    
    def __init__(self, key):
        """Создание шифра с заданным ключом.
        
        Принимает: key - ключ шифрования (16, 24 или 32 байта)
        """
        self.key = key
        self.block_size = 16
    
    def encrypt(self, plaintext):
        """Шифрование данных с генерацией случайного IV.
        
        Принимает: plaintext - исходные данные (байты)
        Возвращает: (iv, ciphertext) - вектор инициализации и шифротекст
        """
        iv = os.urandom(self.block_size)
        cipher = Cipher(algorithms.Camellia(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        padder = padding.ANSIX923(self.block_size * 8).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv, ciphertext
    
    def decrypt(self, ciphertext, iv):
        """Дешифрование данных.
        
        Принимает: ciphertext - зашифрованные данные, iv - вектор инициализации
        Возвращает: расшифрованные данные (байты)
        """
        cipher = Cipher(algorithms.Camellia(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.ANSIX923(self.block_size * 8).unpadder()
        plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
        return plaintext


def generate_camellia_key(key_size=256):
    """Генерация случайного ключа Camellia.
    
    Принимает: key_size - длина ключа в битах (128, 192, 256)
    Возвращает: ключ в байтах
    """
    key_bytes = key_size // 8
    return os.urandom(key_bytes)