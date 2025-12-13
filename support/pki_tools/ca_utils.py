from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import datetime

def gerar_par_chaves():

    # Gera uma chave ECC P-521
    return ec.generate_private_key(ec.SECP521R1())

def criar_ca(common_name="SIC Root CA"):
    
    # Cria uma CA autoassinada
    private_key = gerar_par_chaves()
    public_key = private_key.public_key()

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .serial_number(x509.random_serial_number())
        .public_key(public_key)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )

    cert = builder.sign(private_key=private_key, algorithm=hashes.SHA512())
    return private_key, cert

def emitir_certificado(ca_private_key, ca_cert, subject_name, is_sink=False, nid=None):
    # Emite um certificado assinado pela CA
    private_key = gerar_par_chaves()
    public_key = private_key.public_key()

    atributos = [x509.NameAttribute(NameOID.COMMON_NAME, subject_name)]
    if nid is not None:
        atributos.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, str(nid)))
    if is_sink:
        atributos.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Sink"))

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name(atributos))
        .issuer_name(ca_cert.subject)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .serial_number(x509.random_serial_number())
        .public_key(public_key)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )

    cert = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA512())
    return private_key, cert

def guardar_chave(key, filename):
    # Guarda chave privada em PEM
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def guardar_cert(cert, filename):
    # Guarda certificado em PEM
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
