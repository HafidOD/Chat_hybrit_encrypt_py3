#pip install cryptography

# Empezaremos generando la clave privada
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

# Importamos Fernet
from cryptography.fernet import Fernet

# Serializacion
from cryptography.hazmat.primitives import serialization

# asignature asimetric
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Funcions
def generate_simetric_object(clave):
  f = Fernet(clave)
  return f 

def simetric_encrypt_message(message, obj_Fernet):
  token = obj_Fernet.encrypt(message)
  return token

def simetric_decrypt_message(token, obj_Fernet):
  plaintext = obj_Fernet.decrypt(token)
  return plaintext

def generate_asimetric_Keys():
  private_key = rsa.generate_private_key(
    public_exponent= 65537,
    key_size= 2048,
    backend= default_backend()
  )

  public_key = private_key.public_key()

  return private_key, public_key

def asimetric_encrypt_message(message, private_key, public_key):
  signature = private_key.sign(
    message,
    padding.PSS(
      mgf=padding.MGF1(hashes.SHA256()),
      salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
  )

  ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
      mgf=padding.MGF1(algorithm=hashes.SHA256()),
      algorithm=hashes.SHA256(),
      label=None
    )
  )

  return ciphertext

def asimetric_decrypt_message(message, private_key):
  plaintext = private_key.decrypt(
    message,
    padding.OAEP(
      mgf=padding.MGF1(algorithm=hashes.SHA256()),
      algorithm=hashes.SHA256(),
      label=None
    )
  )

  return plaintext

def encript_hybrid(message, obj_Fernet, private_key, public_key):
  token = simetric_encrypt_message(message, obj_Fernet)
  hibrid_encrypt_message = asimetric_encrypt_message(token, private_key, public_key)

  return hibrid_encrypt_message

def decrypt_hybrid(message, obj_Fernet, private_key):
  token = asimetric_decrypt_message(message, private_key)
  hibrid_decrypt_message = simetric_decrypt_message(token, obj_Fernet)

  return hibrid_decrypt_message

clave = Fernet.generate_key()
# print("llave generada con fernet {}".format(clave))
key = generate_simetric_object(clave)

private_key, public_key = generate_asimetric_Keys()
# print(private_key ,public_key)

pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# print(pem)

public_key_client = serialization.load_pem_public_key(
  pem,
  backend=default_backend()
)

# print(public_key_client)

encrypt_message = asimetric_encrypt_message(clave, private_key, public_key_client)
# print(encrypt_message)

decrypt_message = asimetric_decrypt_message(encrypt_message, private_key)
# print(decrypt_message)

key2 = generate_simetric_object(decrypt_message)

message = b'prueba de encriptado hibrido'

mensaje_encriptado_hib = encript_hybrid(message, key, private_key, public_key_client)
print(mensaje_encriptado_hib)

mensaje_desencriptado_hib = decrypt_hybrid(mensaje_encriptado_hib, key2, private_key)
print(mensaje_desencriptado_hib)

# print(mensaje_desencriptado_hib)
print(mensaje_desencriptado_hib == message)
