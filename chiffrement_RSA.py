from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
#from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_x509_certificate
from cryptography.x509 import load_pem_x509_certificate
from ldap3 import Server, Connection, MODIFY_REPLACE

# Configuration LDAP
ldap_server = 'ldap://votre-serveur-ldap'
ldap_user = 'cn=admin,dc=exemple,dc=com'
ldap_password = 'mot-de-passe-admin'
ldap_base_dn = 'dc=exemple,dc=com'

# Chemins des certificats utilisateur
user1_cert_path = 'user1_certificate.pem'
user2_cert_path = 'user2_certificate.pem'
ca_cert_path = 'ca_certificate.pem'

def get_certificates():
    # Chargez les certificats depuis les fichiers
    with open(user1_cert_path, 'rb') as file:
        user1_cert_data = file.read()
    with open(user2_cert_path, 'rb') as file:
        user2_cert_data = file.read()
    with open(ca_cert_path, 'rb') as file:
        ca_cert_data = file.read()

    user1_cert = load_pem_x509_certificate(user1_cert_data, default_backend())
    user2_cert = load_pem_x509_certificate(user2_cert_data, default_backend())
    ca_cert = load_pem_x509_certificate(ca_cert_data, default_backend())

    return user1_cert, user2_cert, ca_cert

def encrypt_message(message, recipient_cert):
    # Chargez la clé publique du destinataire
    public_key = recipient_cert.public_key()

    # Chiffrez le message
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext

def decrypt_message(ciphertext, private_key):
    # Déchiffrez le message
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext.decode('utf-8')

def store_public_key(username, public_key):
    # Connectez-vous au serveur LDAP
    server = Server(ldap_server)
    connection = Connection(server, ldap_user, ldap_password, auto_bind=True)

    # Convertissez la clé publique au format PEM
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Mettez à jour ou ajoutez la clé publique de l'utilisateur dans LDAP
    connection.modify(
        dn=f'cn={username},{ldap_base_dn}',
        changes={'userCertificate;binary': [(MODIFY_REPLACE, [public_key_pem])]}
    )

    connection.unbind()

if __name__ == '__main__':
    user1_cert, user2_cert, ca_cert = get_certificates()

    # Exemple d'utilisation
    message_to_encrypt = "Salut, Utilisateur2!"

    # L'utilisateur1 (expéditeur) chiffre le message
    ciphertext = encrypt_message(message_to_encrypt, user2_cert)

    # L'utilisateur2 (destinataire) déchiffre le message
    decrypted_message = decrypt_message(ciphertext, load_pem_private_key(user2_private_key, password=None, backend=default_backend()))

    print(f"Message chiffré : {ciphertext}")
    print(f"Message déchiffré : {decrypted_message}")

    # Stockez la clé publique de l'utilisateur1 dans LDAP (remplacez par votre nom d'utilisateur LDAP)
    store_public_key('Utilisateur1', user1_cert.public_key())
