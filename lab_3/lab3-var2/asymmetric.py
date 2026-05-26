import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class RSACipher:
    """Реализация асимметричного шифрования алгоритмом RSA.
    
    Этот класс отвечает за всю работу с RSA:
    - генерация ключей
    - сохранение и загрузка ключей
    - шифрование и дешифрование
    """
    
    def __init__(self, key_size=2048, config_path='config.json'):
        """Инициализация RSA.
        
        Принимает:
            key_size: размер ключа в битах (по умолчанию 2048)
            config_path: путь к файлу конфигурации
        
        Возвращает: None
        """
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self):
        """Генерация пары ключей RSA.
        
        Принимает: None
        Возвращает: (private_key, public_key) - кортеж из закрытого и открытого ключей
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=self.config['rsa_public_exponent'],
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key
    
    def save_private_key(self, file_path):
        """Сохранение закрытого ключа в PEM формат.
        
        Принимает: file_path - путь для сохранения ключа
        Возвращает: None
        
        """
        with open(file_path, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
    
    def save_public_key(self, file_path):
        """Сохранение открытого ключа в PEM формат.
        
        Принимает: file_path - путь для сохранения ключа
        Возвращает: None
        
        """

        with open(file_path, 'wb') as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    @staticmethod
    def load_private_key(file_path):
        """Загрузка закрытого ключа из PEM файла.
        
        Принимает: file_path - путь к PEM файлу
        Возвращает: загруженный закрытый ключ
        
        """
        with open(file_path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    
    @staticmethod
    def load_public_key(file_path):
        """Загрузка открытого ключа из PEM файла.
        
        Принимает: file_path - путь к PEM файлу
        Возвращает: загруженный открытый ключ
        """
        with open(file_path, 'rb') as f:
            return serialization.load_pem_public_key(f.read())
    
    @staticmethod
    def encrypt(public_key, plaintext):
        """Шифрование данных открытым ключом (OAEP с SHA-256).
        
        Принимает:
            public_key: открытый ключ RSA
            plaintext: данные для шифрования (байты)
        Возвращает: зашифрованные данные (байты)
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
        """Дешифрование данных закрытым ключом.
        
        Принимает:
            private_key: закрытый ключ RSA
            ciphertext: зашифрованные данные (байты)
        Возвращает: расшифрованные данные (байты)
        """
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )