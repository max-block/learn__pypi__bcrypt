import bcrypt

password = "mega-password"

password_hash = bcrypt.hashpw(str.encode(password), bcrypt.gensalt()).decode()
print(password_hash)  # $2b$12$xolkczLCSLfsj6ebv6aQ9u1XzaVlmFz0g89s9hpNNw65ANhVBFOlC

res = bcrypt.checkpw(password.encode(), password_hash.encode())
print(res)  # True
