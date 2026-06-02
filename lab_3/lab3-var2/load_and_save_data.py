import json
import os
from cryptography.hazmat.primitives import serialization


def load_json(file_path):
    """Загрузить данные из JSON файла.
    
    Аргументы:
        file_path: путь к JSON файлу
    
    Возвращает:
        dict: загруженные данные
    
    Исключения:
        FileNotFoundError: если файл не найден
        json.JSONDecodeError: если файл содержит некорректный JSON
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json(data, file_path, indent=4):
    """Сохранить данные в JSON файл.
    
    Аргументы:
        data: словарь для сохранения
        file_path: путь для сохранения
        indent: отступы для форматирования
    """
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        print(f"Данные сохранены в {file_path}")
    except Exception as e:
        print(f"Ошибка при сохранении JSON в {file_path}: {e}")
        raise


def load_pem_private_key(file_path):
    """Загрузить закрытый ключ из PEM файла.
    
    Аргументы:
        file_path: путь к PEM файлу
    
    Возвращает:
        PrivateKey: загруженный ключ
    """
    with open(file_path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_pem_public_key(file_path):
    """Загрузить открытый ключ из PEM файла.
    
    Аргументы:
        file_path: путь к PEM файлу
    
    Возвращает:
        PublicKey: загруженный ключ
    """
    with open(file_path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())


def save_pem_private_key(private_key, file_path):
    """Сохранить закрытый ключ в PEM файл.
    
    Аргументы:
        private_key: закрытый ключ
        file_path: путь для сохранения
    """
    with open(file_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))


def save_pem_public_key(public_key, file_path):
    """Сохранить открытый ключ в PEM файл.
    
    Аргументы:
        public_key: открытый ключ
        file_path: путь для сохранения
    """
    with open(file_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def file_exists(file_path):
    """Проверить существование файла.
    
    Аргументы:
        file_path: путь к файлу
    
    Возвращает:
        bool: True если файл существует, иначе False
    """
    return os.path.exists(file_path)


def get_file_size(file_path):
    """Получить размер файла в байтах.
    
    Аргументы:
        file_path: путь к файлу
    
    Возвращает:
        int: размер файла в байтах или 0, если файл не существует
    """
    if file_exists(file_path):
        return os.path.getsize(file_path)
    return 0


def ensure_directory_exists(file_path):
    """Создать директорию для файла, если она не существует.
    
    Аргументы:
        file_path: путь к файлу
    """
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Создана директория: {directory}")