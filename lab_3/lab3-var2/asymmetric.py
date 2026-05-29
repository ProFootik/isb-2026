from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class RSACipher:
    """Класс для шифрования алгоритмом RSA."""
    
    def __init__(self, key_size=2048):
        """Инициализация.
        
        Принимает: key_size - размер ключа в битах
        """
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self):
        """Генерация пары ключей RSA.
        
        Возвращает: (private_key, public_key)
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key
    
    def save_public_key(self, file_path):
        """Сохранить открытый ключ в PEM файл."""
        with open(file_path, 'wb') as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    def save_private_key(self, file_path):
        """Сохранить закрытый ключ в PEM файл."""
        with open(file_path, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
    
    @staticmethod
    def load_private_key(file_path):
        """Загрузить закрытый ключ из PEM файла."""
        with open(file_path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    
    @staticmethod
    def load_public_key(file_path):
        """Загрузить открытый ключ из PEM файла."""
        with open(file_path, 'rb') as f:
            return serialization.load_pem_public_key(f.read())
    
    @staticmethod
    def encrypt(public_key, data):
        """Зашифровать данные открытым ключом (RSA-OAEP).
        
        Принимает: public_key - открытый ключ, data - данные (байты)
        Возвращает: зашифрованные данные
        """
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @staticmethod
    def decrypt(private_key, data):
        """Расшифровать данные закрытым ключом."""
        return private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )