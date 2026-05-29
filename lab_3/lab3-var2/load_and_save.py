import json
import os


def load_json(file_path):
    """Загрузить данные из JSON файла.
    
    Принимает: file_path - путь к файлу
    Возвращает: словарь с данными или None
    """
    if not os.path.exists(file_path):
        return None
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print("Ошибка: неверный формат JSON в файле {}".format(file_path))
        return None


def save_json(data, file_path):
    """Сохранить данные в JSON файл.
    
    Принимает: data - словарь, file_path - путь для сохранения
    """
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print("Настройки сохранены в {}".format(file_path))


def load_bytes(file_path):
    """Загрузить байтовые данные из файла.
    
    Принимает: file_path - путь к файлу
    Возвращает: байты или None
    """
    if not os.path.exists(file_path):
        return None
    
    with open(file_path, 'rb') as f:
        return f.read()


def save_bytes(data, file_path):
    """Сохранить байтовые данные в файл.
    
    Принимает: data - байты, file_path - путь для сохранения
    """
    with open(file_path, 'wb') as f:
        f.write(data)
    print("Файл сохранен: {}".format(file_path))


def load_text(file_path):
    """Загрузить текстовый файл.
    
    Принимает: file_path - путь к файлу
    Возвращает: строку или None
    """
    if not os.path.exists(file_path):
        return None
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()


def save_text(text, file_path):
    """Сохранить текст в файл.
    
    Принимает: text - строка, file_path - путь для сохранения
    """
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(text)
    print("Файл сохранен: {}".format(file_path))


def check_file_exists(file_path):
    """Проверить существование файла.
    
    Принимает: file_path - путь к файлу
    Возвращает: True если файл существует
    """
    return os.path.exists(file_path)


def get_file_size(file_path):
    """Получить размер файла в байтах.
    
    Принимает: file_path - путь к файлу
    Возвращает: размер в байтах или 0
    """
    if os.path.exists(file_path):
        return os.path.getsize(file_path)
    return 0