import hashlib, secrets

with open('top-10000-passwords.txt', 'r', encoding="UTF-8") as f:
        passwords = f.read().splitlines()
with open('known-salts.txt', 'r', encoding="UTF-8") as f:
    salts = f.read().splitlines()


def compare_pass_hash(password, hash):
    hashed_pass = hashlib.sha1(str(password).encode())
    if hashed_pass.hexdigest() == hash:
            return True
    return False

def crack_sha1_hash(hash, use_salts = False):
    
    for password in passwords:
        if use_salts:
            for salt in salts:

                if compare_pass_hash(salt + password, hash) or compare_pass_hash(password + salt, hash):

                    return password
                
        elif compare_pass_hash(password, hash):

            return password

    return "PASSWORD NOT IN DATABASE"