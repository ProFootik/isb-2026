import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class RSACipher:
    """Реализация асимметричного шифрования алгоритмом RSA.
    
    Основан на сложности факторизации больших чисел.
    Использует схему OAEP с SHA-256 для защиты от атак.
    """
    
    def __init__(self, key_size=2048, config_path='config.json'):
        """Инициализация RSA.
        
        Аргументы:
            key_size: размер ключа в битах (по умолчанию 2048)
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
        
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self):
        """Генерация пары ключей RSA.
        
        Возвращает:
            tuple: (private_key, public_key) - кортеж из закрытого и открытого ключей
        """
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=self.config['rsa_public_exponent'],
                key_size=self.key_size
            )
            self.public_key = self.private_key.public_key()
            return self.private_key, self.public_key
        except Exception as e:
            print(f"Ошибка при генерации ключей RSA: {e}")
            raise
    
    def save_private_key(self, file_path):
        """Сохранить закрытый ключ в PEM файл.
        
        Аргументы:
            file_path: путь для сохранения закрытого ключа
        """
        try:
            with open(file_path, 'wb') as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        except IOError as e:
            print(f"Ошибка при сохранении закрытого ключа в {file_path}: {e}")
            raise
        except Exception as e:
            print(f"Неожиданная ошибка при сохранении закрытого ключа: {e}")
            raise
    
    def save_public_key(self, file_path):
        """Сохранить открытый ключ в PEM файл.
        
        Аргументы:
            file_path: путь для сохранения открытого ключа
        """
        try:
            with open(file_path, 'wb') as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
        except IOError as e:
            print(f"Ошибка при сохранении открытого ключа в {file_path}: {e}")
            raise
        except Exception as e:
            print(f"Неожиданная ошибка при сохранении открытого ключа: {e}")
            raise
    
    @staticmethod
    def load_private_key(file_path):
        """Загрузить закрытый ключ из PEM файла.
        
        Аргументы:
            file_path: путь к PEM файлу с закрытым ключом
        
        Возвращает:
            PrivateKey: загруженный закрытый ключ
        """
        try:
            with open(file_path, 'rb') as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        except FileNotFoundError:
            print(f"Ошибка: файл {file_path} не найден")
            raise
        except Exception as e:
            print(f"Ошибка при загрузке закрытого ключа: {e}")
            raise
    
    @staticmethod
    def load_public_key(file_path):
        """Загрузить открытый ключ из PEM файла.
        
        Аргументы:
            file_path: путь к PEM файлу с открытым ключом
        
        Возвращает:
            PublicKey: загруженный открытый ключ
        """
        try:
            with open(file_path, 'rb') as f:
                return serialization.load_pem_public_key(f.read())
        except FileNotFoundError:
            print(f"Ошибка: файл {file_path} не найден")
            raise
        except Exception as e:
            print(f"Ошибка при загрузке открытого ключа: {e}")
            raise
    
    @staticmethod
    def encrypt(public_key, plaintext):
        """Зашифровать данные открытым ключом (OAEP с SHA-256).
        
        Аргументы:
            public_key: открытый ключ RSA
            plaintext: данные для шифрования (байты)
        
        Возвращает:
            bytes: зашифрованные данные
        """
        try:
            return public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            print(f"Ошибка при шифровании RSA: {e}")
            raise
    
    @staticmethod
    def decrypt(private_key, ciphertext):
        """Расшифровать данные закрытым ключом.
        
        Аргументы:
            private_key: закрытый ключ RSA
            ciphertext: зашифрованные данные (байты)
        
        Возвращает:
            bytes: расшифрованные данные
        """
        try:
            return private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            print(f"Ошибка при дешифровании RSA: {e}")
            raise