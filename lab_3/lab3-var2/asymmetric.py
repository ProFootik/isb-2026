from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class RSACipher:
    """Реализация асимметричного шифрования алгоритмом RSA"""
    
    def __init__(self, key_size=2048):
        """Инициализация RSA.
        
        Принимает: key_size - размер ключа в битах
        Возвращает: None
        """
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self):
        """Генерация пары ключей.
        
        Принимает: None
        Возвращает: (private_key, public_key)
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key
    
    def save_private_key(self, file_path):
        """Сохранение закрытого ключа.
        
        Принимает: file_path - путь для сохранения
        Возвращает: None
        """
        with open(file_path, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
    
    def save_public_key(self, file_path):
        """Сохранение открытого ключа.
        
        Принимает: file_path - путь для сохранения
        Возвращает: None
        """
        with open(file_path, 'wb') as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    @staticmethod
    def load_private_key(file_path):
        """Загрузка закрытого ключа.
        
        Принимает: file_path - путь к файлу
        Возвращает: private_key
        """
        with open(file_path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    
    @staticmethod
    def load_public_key(file_path):
        """Загрузка открытого ключа.
        
        Принимает: file_path - путь к файлу
        Возвращает: public_key
        """
        with open(file_path, 'rb') as f:
            return serialization.load_pem_public_key(f.read())
    
    @staticmethod
    def encrypt(public_key, plaintext):
        """Шифрование данных.
        
        Принимает: public_key - открытый ключ, plaintext - данные
        Возвращает: зашифрованные данные
        """
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @staticmethod
    def decrypt(private_key, ciphertext):
        """Дешифрование данных.
        
        Принимает: private_key - закрытый ключ, ciphertext - зашифрованные данные
        Возвращает: расшифрованные данные
        """
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )