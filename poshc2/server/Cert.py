from os.path import exists, join

from OpenSSL import crypto

from poshc2.server.Config import Cert_C, Cert_ST, Cert_L, Cert_O, Cert_OU, Cert_CN, Cert_SerialNumber, Cert_NotBefore, Cert_NotAfter

CERT_FILE = "posh.crt"
KEY_FILE = "posh.key"


def create_self_signed_cert(cert_dir):
    """
    If datacard.crt and datacard.key don't exist in cert_dir, create a new
    self-signed cert and keypair and write them into that directory.

    easy_install pyopenssl
    """

    if not exists(join(cert_dir, CERT_FILE)) or not exists(join(cert_dir, KEY_FILE)):
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = Cert_C
        cert.get_subject().ST = Cert_ST
        cert.get_subject().L = Cert_L
        cert.get_subject().O = Cert_O
        cert.get_subject().OU = Cert_OU
        cert.get_subject().CN = Cert_CN
        cert.set_serial_number(Cert_SerialNumber)
        cert.gmtime_adj_notBefore(Cert_NotBefore)
        cert.gmtime_adj_notAfter(Cert_NotAfter)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')

        open(join(cert_dir, CERT_FILE), "wb").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        open(join(cert_dir, KEY_FILE), "wb").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
