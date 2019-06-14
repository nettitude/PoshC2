#!/usr/bin/env python

from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join

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
    cert.get_subject().C = "US"
    cert.get_subject().ST = "Minnesota"
    cert.get_subject().L = "Minnetonka"
    cert.get_subject().O = "Pajfds"
    cert.get_subject().OU = "Jethpro"
    cert.get_subject().CN = "P18055077"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha1')

    open(join(cert_dir, CERT_FILE), "wb").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(join(cert_dir, KEY_FILE), "wb").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
