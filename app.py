# Importamos Fernet
from cryptography.fernet import Fernet

# Empezaremos generando la clave privada
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

# Generamos una clave
clave = Fernet.generate_key()
# clave2 = Fernet.generate_key()
# Creamos la instancia de Fernet
# Parametros: key: clave generada
f = Fernet(clave)
# f2 = Fernet(clave2)

# Encriptamos el mensaje
# utilizando el método "encrypt"
mensaje = b"funciona"
print("mensaje que se va a encriptar:\n{}\n\n".format(mensaje))
token = f.encrypt(mensaje)
# Mostramos el token del mensaje
print("Este es el mensaje ecriptado de manera simetrica:\n{}\n\n".format(token))

# Utilizaremos el método "generate_private_key"
# para generar nuestra clave
# asignamos algunos parametros
private_key = rsa.generate_private_key(
     public_exponent=65537,
     key_size=2048,
     backend=default_backend()
)

# Ahora generaremos la clave pública
public_key = private_key.public_key()

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
# message = b"A message I want to sign"
signature = private_key.sign(
     token,
     padding.PSS(
         mgf=padding.MGF1(hashes.SHA256()),
         salt_length=padding.PSS.MAX_LENGTH
     ),
     hashes.SHA256()
)

"""
Procedemos a cifrar el dato.
Para ello utilizaremos el método encrytp.
"""
#message = b"Dato para cifrar"
ciphertext = public_key.encrypt(
     token,
     padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
     )
 )

print("Este es el token encryotado de manera asimetrica con la llave publica:\n{}\n\n".format(ciphertext))

"""
Ahora vamos a descifrar el mensaje. Para ello utilizaremos el 
método decrypt.
"""
plaintext = private_key.decrypt(
     ciphertext,
     padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
     )
 )

print("Desencriptando con la llave privada:\n{}\n\n".format(plaintext))

# Podemos descifrar el mensaje utilizando 
# el método "decrypt".

des = f.decrypt(plaintext)
print("Desencriptando con la llave simetrica:\n{}\n\n".format(des))