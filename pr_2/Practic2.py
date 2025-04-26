'''
1) написать программную реализацию одной из перечисленных ниже асимметричных криптосистем (по выбору студента) с использованием больших чисел. Программная реализация должна быть выполнена студентом самостоятельно без использования готовых библиотечных функций, напрямую реализующих алгоритм шифрования. Варианты криптосистем для реализации:
- RSA;
- Рабина;
- Эль-Гамаля;


1) принимать на вход файл, содержащий открытый текст, подлежащий зашифрованию, или шифртекст, подлежащий расшифрованию;
2) принимать на вход ключевую пару (открытый ключ, закрытый ключ);
3) давать пользователю возможность сгенерировать ключевую пару;
4) осуществлять зашифрование или расшифрование введенного текста по выбору пользователя.
'''


import random
import math

def generate_prime(bits):
    """Генерация простого числа заданной длины"""
    while True:
        p = random.getrandbits(bits)
        if p % 4 == 3 and is_prime(p):
            return p

def is_prime(n, k=20):
    """Тест Миллера-Рабина на простоту"""
    if n < 2: return False
    for p in [2,3,5,7,11,13,17,19,23,29,31]:
        if n % p == 0: return n == p
    
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    
    for _ in range(k):
        a = random.randint(2, min(n - 2, 1 << 20))
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True

def extended_gcd(a, b):
    """Расширенный алгоритм Евклида"""
    if a == 0: return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def generate_keys(bit_length=256):
    """Генерация ключевой пары"""
    p = generate_prime(bit_length // 2)
    q = generate_prime(bit_length // 2)
    while p == q:
        q = generate_prime(bit_length // 2)
    n = p * q
    return (n, (p, q))

def encrypt(m, n):
    """Шифрование сообщения"""
    if m >= n:
        raise ValueError("Сообщение должно быть меньше модуля n")
    return pow(m, 2, n)

def decrypt(c, p, q):
    """Дешифрование сообщения"""
    n = p * q
    mp = pow(c, (p + 1)//4, p)
    mq = pow(c, (q + 1)//4, q)
    
    gcd, yp, yq = extended_gcd(p, q)
    
    d1 = (yp * p * mq + yq * q * mp) % n
    d2 = n - d1
    d3 = (yp * p * mq - yq * q * mp) % n
    d4 = n - d3
    
    return sorted([d1, d2, d3, d4])

def text_to_num(text):
    """Преобразование текста в число"""
    return int.from_bytes(text.encode('utf-8'), 'big')

def num_to_text(num):
    """Преобразование числа в текст"""
    byte_length = (num.bit_length() + 7) // 8
    return num.to_bytes(byte_length, 'big').decode('utf-8', errors='ignore')

def main():
    print("1. Шифрование файла")
    print("2. Дешифрование файла")
    print("3. Генерация ключей")
    choice = input("Выберите действие: ")
    
    if choice == '3':
        bits = int(input("Введите длину ключа в битах (рекомендуется 256+): "))
        n, (p, q) = generate_keys(bits)
        with open('public.key', 'w') as f:
            f.write(f"{n}")
        with open('private.key', 'w') as f:
            f.write(f"{p}\n{q}")
        print(f"Ключи сгенерированы и сохранены в public.key и private.key")
        return
    
    if choice == '1':
        pub_key = int(open('public.key').read().strip())
        with open(input("Введите имя файла: "), 'r') as f:
            plaintext = f.read()
        m = text_to_num(plaintext)
        c = encrypt(m, pub_key)
        with open('ciphertext.rabin', 'wb') as f:
            f.write(c.to_bytes((c.bit_length() + 7) // 8, 'big'))
        print("Шифрование завершено. Результат в ciphertext.rabin")
    
    elif choice == '2':
        p, q = map(int, open('private.key').read().split())
        with open('ciphertext.rabin', 'rb') as f:
            c = int.from_bytes(f.read(), 'big')
        decrypted = decrypt(c, p, q)
        print("Возможные варианты расшифрованного текста:")
        for i, m in enumerate(decrypted):
            print(f"{i+1}. {num_to_text(m)}")
        
        selected = input("Выберите правильный вариант (1-4): ")
        with open('decrypted.txt', 'w') as f:
            f.write(num_to_text(decrypted[int(selected)-1]))
        print("Результат сохранен в decrypted.txt")

if __name__ == "__main__":
    main()
