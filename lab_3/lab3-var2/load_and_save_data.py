import json
import os
from cryptography.hazmat.primitives import serialization


def save_json(data, file_path, indent=2):
    """Сохранение данных в JSON файл.
    
    Принимает: data - словарь, file_path - путь, indent - отступы
    Возвращает: None
    """

    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)
    print("Данные сохранены в {}".format(file_path))


def load_json(file_path):
    """Загрузка данных из JSON файла.
    
    Принимает: file_path - путь к файлу
    Возвращает: словарь с данными
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError("Файл не найден: {}".format(file_path))
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def ensure_directory_exists(file_path):
    """Создание директории если не существует.
    
    Принимает: file_path - путь к файлу
    Возвращает: None
    """
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
        print("Создана директория: {}".format(directory))
