import socket
import sys

import threading

# Empezaremos generando la clave privada
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

# Serializacion
from cryptography.hazmat.primitives import serialization

# Importamos Fernet
from cryptography.fernet import Fernet

# asignature asimetric
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Funcions simetric y asimetric keys
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
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
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
  hibrid_encrypt_message = asimetric_encrypt_message(
      token, private_key, public_key)

  return hibrid_encrypt_message

def decrypt_hybrid(message, obj_Fernet, private_key):
  token = asimetric_decrypt_message(message, private_key)
  hibrid_decrypt_message = simetric_decrypt_message(token, obj_Fernet)

  return hibrid_decrypt_message

def serealizacion(data):
  public_key_client = serialization.load_pem_public_key(
    data,
    backend=default_backend()
  )
  return public_key_client

def msg_recv():
  while True:
    data = sock.recv(2048)
    if len(data) == 451:
      print("<-- Llave publica recibida -->\n")
      public_key = serealizacion(data)
      session_key = asimetric_encrypt_message(clave, private_key, public_key)
      print("<-- Enviando llave de sesion -->\n")
      # print(session_key)
      sock.sendall(session_key)
      continue
    if data:
      print("Mensaje encriptado recivido: {}\n".format(data))
      msg = simetric_decrypt_message(data, key)
      print("Mensaje desencriptado: {}\n".format(msg))

def send_public_key(public_key_1):
  # Send data
  message = public_key_1
  print('<-- Enviando llave publica -->\n')
  sock.sendall(message)

def send_message(message):
  # Send data
  # print('Enviando mensaje: {!r}'.format(message))
  # print(message)
  msg = simetric_encrypt_message(message, key)
  sock.sendall(msg)

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('localhost', 10000)
print('connecting to {} port {}'.format(*server_address))
sock.connect(server_address)

clave = Fernet.generate_key()
key = generate_simetric_object(clave)

private_key, public_key_1 = generate_asimetric_Keys()

pem = public_key_1.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

public_key = ''

msg_recv = threading.Thread(target=msg_recv)

msg_recv.daemon = True
msg_recv.start()

send_public_key(pem)

while True:
  msg = str.encode(input('->'))
  send_message(msg)
