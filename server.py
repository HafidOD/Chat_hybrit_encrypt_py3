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

# def send_msg(socket, msg):
#   # print(msg)
#   socket.sendall(pickle.dumps(msg))

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

def msg_recv():
  while True:
    msg = str.encode(input('->'))
    send_message(connection, msg, key)

def send_message(connection, message, obj_Fernet):
  # Send data
  # # print(message)
  msg = simetric_encrypt_message(message, key)
  connection.sendall(msg)

def serealizacion(data):
  public_key_client = serialization.load_pem_public_key(
    data,
    backend=default_backend()
  )
  return public_key_client

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('localhost', 10000)
print('starting up on {} port {}'.format(*server_address))
sock.bind(server_address)
private_key, public_key = generate_asimetric_Keys()

pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

public_key_1 = ''
clave = ''
# Listen for incoming connections
sock.listen(2)

msg_recv = threading.Thread(target=msg_recv)

msg_recv.daemon = True
msg_recv.start()

while True:
    # Wait for a connection
    print('\nwaiting for a connection\n')
    connection, client_address = sock.accept()

    try:
        print('connection from', client_address)
        # Receive the data in small chunks and retransmit it
        while True:
            data = connection.recv(2048)
            # print('received {!r}'.format(data))
            if len(data) == 451:
                print("<-- Llave publica recibida -->\n")
                public_key_1 = serealizacion(data)
                print("<-- Llave de sesion recivida -->\n")
                connection.sendall(pem)
                # time.sleep(.2) 
                session_key = connection.recv(2048)
                session_key = asimetric_decrypt_message(session_key, private_key)
                clave = session_key
                key = generate_simetric_object(clave)
                continue
            if data:
                print("Mensaje encriptado recivido: {}\n".format(data))
                msg = simetric_decrypt_message(data, key)
                print("Mensaje desencriptado: {}\n".format(msg))
            else:
                print('no data from', client_address)
                break

    finally:
        # Clean up the connection
        connection.close()
