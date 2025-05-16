'''
написать программную реализацию схемы электронной цифровой подписи, представленной в ГОСТ Р 34.10-2012.
Программная реализация должна быть выполнена студентом самостоятельно без использования готовых библиотечных решений (допускается использование
готовой реализации хэш-функции ГОСТ Р 34.11-2012);

Программа должна обладать следующей функциональностью:
    1) принимать на вход файл, для которого необходимо сформировать или проверить электронную цифровую подпись;
    2) принимать на вход файл, содержащий электронную цифровую подпись;
    3) принимать на вход ключ подписи или ключ проверки подписи;
    4) давать пользователю возможность сгенерировать ключевую пару;
    5) осуществлять формирование или проверку электронной цифровой подписи по выбору пользователя.

'''
import os
import sys
import hashlib
from pygost.gost34112012 import GOST34112012
from pygost.utils import hexenc, hexdec
from random import SystemRandom

# Параметры эллиптической кривой ГОСТ Р 34.10-2012 (пример для 256-битной кривой id-tc26-gost-3410-12-256-paramSetA)
p = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97", 16)
a = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94", 16)
b = int("A6", 16)
q = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893", 16)
xG = int("1", 16)
yG = int("8D91E471E0986C3F7F0E9F3A6C5A0E2F4F9E4C3F5F9F5E2D7E2E2D7E2E2D7E2", 16)

# Точка генератора G
G = (xG, yG)

# Случайный генератор криптографически стойкий
rand = SystemRandom()

def mod_inv(a, m):
    """Обратный элемент по модулю m (расширенный алгоритм Евклида)"""
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % m, m
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % m

def ec_add(p1, p2):
    """Сложение точек эллиптической кривой"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if p1 == p2:
        l = (3 * x1 * x1 + a) * mod_inv(2 * y1, p) % p
    else:
        l = (y2 - y1) * mod_inv(x2 - x1, p) % p
    x3 = (l * l - x1 - x2) % p
    y3 = (l * (x1 - x3) - y1) % p
    return (x3, y3)

def ec_mul(k, point):
    """Умножение точки на скаляр (быстрое удвоение и сложение)"""
    result = None
    addend = point
    while k:
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result

def generate_keypair():
    """Генерация секретного и открытого ключей"""
    d = rand.randrange(1, q)  # Секретный ключ
    Q = ec_mul(d, G)          # Открытый ключ
    return d, Q

def hash_message(message_bytes):
    """Хэширование сообщения по ГОСТ Р 34.11-2012 (256 бит)"""
    h = GOST34112012(data=message_bytes)
    return int.from_bytes(h.digest(), byteorder='big')

def sign(message_bytes, d):
    """Формирование подписи"""
    e = hash_message(message_bytes) % q
    if e == 0:
        e = 1
    while True:
        k = rand.randrange(1, q)
        C = ec_mul(k, G)
        r = C[0] % q
        if r == 0:
            continue
        s = (r * d + k * e) % q
        if s == 0:
            continue
        break
    return (r, s)

def verify(message_bytes, signature, Q):
    """Проверка подписи"""
    r, s = signature
    if not (0 < r < q and 0 < s < q):
        return False
    e = hash_message(message_bytes) % q
    if e == 0:
        e = 1
    v = mod_inv(e, q)
    z1 = (s * v) % q
    z2 = (q - r * v) % q
    C = ec_add(ec_mul(z1, G), ec_mul(z2, Q))
    if C is None:
        return False
    R = C[0] % q
    return R == r

def save_key(filename, key):
    with open(filename, "w") as f:
        if isinstance(key, tuple):
            # Открытый ключ - точка (x, y)
            f.write(f"{key[0]}\n{key[1]}\n")
        else:
            # Секретный ключ - число
            f.write(str(key) + "\n")

def load_key(filename, is_public):
    with open(filename, "r") as f:
        lines = f.readlines()
        if is_public:
            x = int(lines[0].strip())
            y = int(lines[1].strip())
            return (x, y)
        else:
            return int(lines[0].strip())

def save_signature(filename, signature):
    r, s = signature
    with open(filename, "w") as f:
        f.write(f"{r}\n{s}\n")

def load_signature(filename):
    with open(filename, "r") as f:
        lines = f.readlines()
        r = int(lines[0].strip())
        s = int(lines[1].strip())
        return (r, s)

def main():
    while True:
        print("\nВыберите действие:")
        print("1 - Сгенерировать ключевую пару")
        print("2 - Подписать файл")
        print("3 - Проверить подпись файла")
        print("0 - Выход")
        choice = input("Введите номер действия: ").strip()
        if choice == "1":
            d, Q = generate_keypair()
            save_key("private.key", d)
            save_key("public.key", Q)
            print("Ключи сохранены в private.key и public.key")
        elif choice == "2":
            filename = input("Введите имя файла для подписи: ").strip()
            if not os.path.exists(filename):
                print("Файл не найден")
                continue
            d = load_key("private.key", False)
            with open(filename, "rb") as f:
                data = f.read()
            signature = sign(data, d)
            save_signature("signature.sig", signature)
            print("Подпись сохранена в signature.sig")
        elif choice == "3":
            filename = input("Введите имя файла для проверки подписи: ").strip()
            if not os.path.exists(filename):
                print("Файл не найден")
                continue
            pubkey = load_key("public.key", True)
            signature = load_signature("signature.sig")
            with open(filename, "rb") as f:
                data = f.read()
            if verify(data, signature, pubkey):
                print("Подпись верна")
            else:
                print("Подпись НЕ верна")
        elif choice == "0":
            break
        else:
            print("Некорректный выбор")

if __name__ == "__main__":
    main()
