from cryptography.hazmat.primitives.asymmetric import rsa

from load_and_save_data import load_json

class RSACipher:
    """Реализация асимметричного шифрования алгоритмом RSA."""
    
    def __init__(self, key_size=2048, config_path='config.json'):
        """Инициализация RSA.
        
        Аргументы:
            key_size: размер ключа в битах (по умолчанию 2048)
            config_path: путь к файлу конфигурации
        """
        self.config = load_json(config_path)
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self):
        """Генерация пары ключей RSA.
        
        Возвращает:
            tuple: (private_key, public_key)
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=self.config['rsa_public_exponent'],
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key