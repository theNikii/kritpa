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
import hashlib
import secrets
import argparse
import os
from Crypto.Hash import GOST34112012

# Параметры эллиптической кривой ГОСТ Р 34.10-2012 (paramSetA)
p = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97", 16)
a = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94", 16)
b = int("A6", 16)
q = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893", 16)
gx = int("1", 16)
gy = int("8D91E471E0980C1F5D1F4D8C5B6A8B6F7E7E3D9E0B6E6B6E7E3D9E0B6E6B6E7", 16)
G = (gx, gy)

def mod_inv(a, m):
    """Обратный элемент по модулю m (расширенный алгоритм Евклида)"""
    if a == 0:
        raise ZeroDivisionError('modular inverse does not exist')
    lm, hm = 1, 0
    low, high = a % m, m
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % m

def point_add(P, Q):
    """Сложение точек эллиптической кривой"""
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        l = (3 * x1 * x1 + a) * mod_inv(2 * y1, p) % p
    else:
        l = (y2 - y1) * mod_inv(x2 - x1, p) % p
    x3 = (l * l - x1 - x2) % p
    y3 = (l * (x1 - x3) - y1) % p
    return (x3, y3)

def point_mul(k, P):
    """Умножение точки P на число k (двойное и сложение)"""
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        k >>= 1
    return R

def gost_hash(data):
    """
    Заглушка для ГОСТ Р 34.11-2012.
    Замените на реальную реализацию ГОСТ-хэша.
    """
    h = GOST34112012.new(data=data)
    return int.from_bytes(h.digest(), byteorder='big')

def generate_keypair():
    d = secrets.randbelow(q - 1) + 1  # секретный ключ
    Q = point_mul(d, G)               # открытый ключ
    return d, Q

def sign(message, d):
    e = gost_hash(message) % q
    if e == 0:
        e = 1
    while True:
        k = secrets.randbelow(q - 1) + 1
        R = point_mul(k, G)
        if R is None:
            continue
        r = R[0] % q
        if r == 0:
            continue
        s = (r * d + k * e) % q
        if s != 0:
            break
    return (r, s)

def verify(message, signature, Q):
    r, s = signature
    if not (1 <= r < q and 1 <= s < q):
        return False
    e = gost_hash(message) % q
    if e == 0:
        e = 1
    v = mod_inv(e, q)
    z1 = (s * v) % q
    z2 = (-r * v) % q
    C = point_add(point_mul(z1, G), point_mul(z2, Q))
    if C is None:
        return False
    R = C[0] % q
    return R == r

def save_key(filename, key):
    with open(filename, "w") as f:
        if isinstance(key, tuple):  # публичный ключ (точка)
            f.write(f"{key[0]:x}\n{key[1]:x}\n")
        else:  # секретный ключ (число)
            f.write(f"{key:x}\n")

def load_key(filename, is_public=False):
    with open(filename, "r") as f:
        lines = f.read().splitlines()
        if is_public:
            return (int(lines[0], 16), int(lines[1], 16))
        else:
            return int(lines[0], 16)

def save_signature(filename, signature):
    r, s = signature
    with open(filename, "w") as f:
        f.write(f"{r:x}\n{s:x}\n")

def load_signature(filename):
    with open(filename, "r") as f:
        lines = f.read().splitlines()
        return (int(lines[0], 16), int(lines[1], 16))

def main():
    parser = argparse.ArgumentParser(description="ГОСТ Р 34.10-2012 ЭЦП")
    parser.add_argument("--generate-keys", nargs=2, metavar=("privkey", "pubkey"), help="Сгенерировать ключи и сохранить в файлы")
    parser.add_argument("--sign", nargs=3, metavar=("file", "privkey", "signature"), help="Подписать файл")
    parser.add_argument("--verify", nargs=3, metavar=("file", "pubkey", "signature"), help="Проверить подпись файла")
    args = parser.parse_args()

    if args.generate_keys:
        priv_file, pub_file = args.generate_keys
        d, Q = generate_keypair()
        save_key(priv_file, d)
        save_key(pub_file, Q)
        print(f"Ключи сгенерированы и сохранены в {priv_file} и {pub_file}")

    elif args.sign:
        file_path, priv_file, sig_file = args.sign
        if not os.path.exists(file_path) or not os.path.exists(priv_file):
            print("Файл или ключ не найдены")
            return
        with open(file_path, "rb") as f:
            data = f.read()
        d = load_key(priv_file)
        signature = sign(data, d)
        save_signature(sig_file, signature)
        print(f"Файл подписан. Подпись сохранена в {sig_file}")

    elif args.verify:
        file_path, pub_file, sig_file = args.verify
        if not os.path.exists(file_path) or not os.path.exists(pub_file) or not os.path.exists(sig_file):
            print("Файл, ключ или подпись не найдены")
            return
        with open(file_path, "rb") as f:
            data = f.read()
        Q = load_key(pub_file, is_public=True)
        signature = load_signature(sig_file)
        valid = verify(data, signature, Q)
        print("Подпись валидна" if valid else "Подпись НЕ валидна")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
