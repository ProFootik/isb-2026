import json
import os
from cryptography.hazmat.primitives import serialization


def save_json(data, file_path, indent=2):
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)
    print("Данные сохранены в {}".format(file_path))


def load_json(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError("Файл не найден: {}".format(file_path))
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_bytes(data, file_path):
    with open(file_path, 'wb') as f:
        f.write(data)
    print("Данные ({} байт) сохранены в {}".format(len(data), file_path))


def load_bytes(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError("Файл не найден: {}".format(file_path))
    
    with open(file_path, 'rb') as f:
        return f.read()


def save_pem_key(key, file_path, key_type='public'):
    with open(file_path, 'wb') as f:
        if key_type == 'public':
            f.write(key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        else:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
    print("{} ключ сохранен в {}".format(key_type.capitalize(), file_path))


def load_pem_public_key(file_path):
    with open(file_path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())


def load_pem_private_key(file_path, password=None):
    with open(file_path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=password)


def ensure_directory_exists(file_path):
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
        print("Создана директория: {}".format(directory))


def get_file_size(file_path):
    if os.path.exists(file_path):
        return os.path.getsize(file_path)
    return 0