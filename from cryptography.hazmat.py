from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

# Générer une paire de clés (clé privée et clé publique)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# La phrase que vous voulez hacher et signer
phrase = "Ceci est une phrase de grande taille que nous voulons hacher."

# Hacher la phrase avec SHA-256
digest = hashes.Hash(hashes.SHA256())
digest.update(phrase.encode('utf-8'))
hash_value = digest.finalize()

# Signer le hachage avec la clé privée
signature = private_key.sign(
    hash_value,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Vous pouvez enregistrer la signature et le hachage pour vérification ultérieure

# Vérifier la signature avec la clé publique
public_key = private_key.public_key()
try:
    public_key.verify(
        signature,
        hash_value,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("La signature est valide.")
except Exception:
    print("La signature est invalide.")
