from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib



def generate_key_pair():
    # Genel ve özel anahtar çiftini oluştur
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()

    # Anahtarları ekrana yaz
    pem_private = private_key.export_key().decode('utf-8')
    pem_public = public_key.export_key().decode('utf-8')

    print("Private Key:")
    print(pem_private)
    print("\nPublic Key:")
    print(pem_public)
    print("\nHash")
    print(hashlib.sha256(pem_public.encode('utf-8')).hexdigest())

generate_key_pair()  # generate_key_pair fonksiyonunu çağır

print("\nŞu ana kadar keylerimizi oluşturup hashledik. Bundan sonra bu keyler ile bir doğrulama yapacağız.")

def generate_key_pair2():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return private_key, public_key

def encrypt_text(public_key, plaintext):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return ciphertext

def decrypt_text(private_key, ciphertext):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')
    return plaintext

# Anahtar çiftini oluştur 
private_key, public_key = generate_key_pair2()

# Metni şifrele
plaintext = "This text is very important"
ciphertext = encrypt_text(public_key, plaintext)
print("\nŞifrelenmiş Metin:", ciphertext)

# Şifreli metni çöz
decrypted_text = decrypt_text(private_key, ciphertext)
print("\nÇözülen Metin:", decrypted_text)

print("\nşimdi de bir anahtar çiftini doğrulama işlemi yapacağız.")


def check_keys():
    # Kullanıcıdan private ve public key'leri alalım
    private_key_input = input("Enter private key (hex format): ").strip()
    public_key_input = input("Enter public key (hex format): ").strip()
    
    # Şifrelenecek mesajı tanımlayalım
    message = "Yeyyy"

    try:
        # Private ve public key'leri RSA objelerine çevirelim
        private_key = RSA.import_key(bytes.fromhex(private_key_input))
        public_key = RSA.import_key(bytes.fromhex(public_key_input))

        # Şifreleme işlemi
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(message.encode('utf-8'))

        # Çözme işlemi
        decipher = PKCS1_OAEP.new(private_key)
        decrypted_message = decipher.decrypt(ciphertext).decode('utf-8')

        # Şifreleme ve çözme işlemleri doğruysa
        if decrypted_message == message:
            print("Keys are correct!")
        else:
            print("Keys are incorrect.")
    except ValueError:
        print("Invalid key format.")
    except Exception as e:
        print("An error occurred:", str(e))

# Fonksiyonu çağıralım
check_keys()

