import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import HybridCryptoSystem
from load_and_save_data import ensure_directory_exists


def create_test_file(file_path):
    """Создание пустого тестового файла"""
    ensure_directory_exists(file_path)
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write("")
    print("Создан пустой тестовый файл: {}".format(file_path))
    return file_path


def run_test():
    """Запуск полного теста гибридной криптосистемы"""
    print("\n" + "="*70)
    print("ТЕСТИРОВАНИЕ ГИБРИДНОЙ КРИПТОСИСТЕМЫ (Camellia + RSA)")
    print("="*70)
    
    test_dir = "test_output"
    ensure_directory_exists("{}/dummy".format(test_dir))
    
    test_files = {
        'public_key': "{}/test_public.pem".format(test_dir),
        'private_key': "{}/test_private.pem".format(test_dir),
        'enc_sym_key': "{}/test_sym_key.enc".format(test_dir),
        'input_file': "{}/test_input.txt".format(test_dir),
        'encrypted_file': "{}/test_encrypted.bin".format(test_dir),
        'decrypted_file': "{}/test_decrypted.txt".format(test_dir)
    }
    
    print("\n1. Создание тестового файла...")
    create_test_file(test_files['input_file'])
    
    print("\n2. Генерация ключей (Camellia-256)...")
    HybridCryptoSystem.generate_keys(
        test_files['public_key'],
        test_files['private_key'],
        test_files['enc_sym_key'],
        sym_key_size=256
    )
    
    print("\n3. Шифрование файла...")
    HybridCryptoSystem.encrypt_file(
        test_files['input_file'],
        test_files['encrypted_file'],
        test_files['enc_sym_key'],
        test_files['private_key']
    )
    
    print("\n4. Дешифрование файла...")
    HybridCryptoSystem.decrypt_file(
        test_files['encrypted_file'],
        test_files['decrypted_file'],
        test_files['enc_sym_key'],
        test_files['private_key']
    )
    
    print("\n5. Проверка результата...")
    
    with open(test_files['input_file'], 'rb') as f:
        original = f.read()
    
    with open(test_files['decrypted_file'], 'rb') as f:
        decrypted = f.read()
    
    if original == decrypted:
        print("ТЕСТ ПРОЙДЕН: Исходный и расшифрованный файлы совпадают!")
        print("   Размер файла: {} байт".format(len(original)))
    else:
        print("ТЕСТ НЕ ПРОЙДЕН: Файлы не совпадают!")
        
    print("\n6. Созданные файлы:")
    for name, path in test_files.items():
        if os.path.exists(path):
            size = os.path.getsize(path)
            print("   - {}: {} ({} байт)".format(name, path, size))
        else:
            print("   - {}: {} (НЕ СОЗДАН)".format(name, path))
    
    print("\n" + "="*70)
    print("Тестирование завершено!")


if __name__ == "__main__":
    run_test()