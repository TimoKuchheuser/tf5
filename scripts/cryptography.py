#!/usr/bin/python3
import os
import tarfile
from typing import IO
from base64 import b64encode
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
#from Crypto.Signature import eddsa

project_root = os.path.dirname(os.path.dirname(__file__))
pub_keys_path = os.path.join(project_root, "keys", "public")
priv_keys_path = os.path.join(project_root, "keys", "private")
files_path = os.path.join(project_root, "files")

def create_new_keypair(orig_site: str) -> IO:

    #private key
    priv_key = ECC.generate(curve='ed25519')
    #filename for a site's private key
    priv_filename = orig_site + "_priv.pem"
    #output path
    priv_outpath = os.path.join(priv_keys_path, priv_filename)
    
    #if the private key doesn't already exist
    if not os.path.isfile(priv_outpath):
        with open(priv_outpath, "wt") as f:
            f.write(priv_key.export_key(format="PEM"))

    #matching private key
    pub_key = priv_key.public_key()
    pub_filename = orig_site + "_pub.pem"
    pub_outpath = os.path.join(pub_keys_path, pub_filename)

    if not os.path.isfile(pub_outpath):
        with open(pub_outpath, "wt") as f:
            f.write(pub_key.export_key(format="PEM"))

def archive_data(uid: str, orig_site: str, receiv_site: str) -> IO:
    #uid/raw, uid/temp and uid/analysed are created by tf5t.py

    #path to raw directory from uid
    raw_dir = os.path.join(files_path, uid, "raw")
    #name of archive
    archive_filename = orig_site + "_" + uid + "_" + receiv_site + ".tar.gz"
    #path to temp directory from uid
    uid_tmp = os.path.join(files_path, uid, "tmp")
    #output path 
    archive_outpath = os.path.join(uid_tmp, archive_filename)

    if not os.path.isfile(archive_outpath):
        with tarfile.open(archive_outpath, "x:gz") as tar:
            tar.add(raw_dir, arcname="")

def create_symmetric_key() -> bytes:
    # Generate a random symmetric key with 64 bytes
    symmetric_key = get_random_bytes(32)
    return symmetric_key

def encrypt_archive(uid: str, orig_site: str, receiv_site: str, symm_key: bytes) -> IO:
    # Path to archive from origin site
    archive_filename = orig_site + "_" + uid + "_" + receiv_site + ".tar.gz"
    uid_tmp = os.path.join(files_path, uid, "tmp")
    archive_outpath = os.path.join(uid_tmp, archive_filename)

    # Read the archive as binary
    with open(archive_outpath, "rb") as f:
        archive = f.read()

    # Create a ChaCha20 cipher using the symmetric key
    cipher = ChaCha20.new(key=symm_key)

    # Encrypt archive
    enc_archive = cipher.encrypt(archive)

    # Base64 encode the encrypted archive
    enc_archive_b64 = b64encode(enc_archive)

    enc_archive_filename = orig_site + "_" + uid + "_" + receiv_site + ".enc"
    enc_archive_outpath = os.path.join(uid_tmp, enc_archive_filename)

    if not os.path.isfile(enc_archive_outpath):
        with open(enc_archive_outpath, "wb") as f:
            f.write(enc_archive_b64) 


def encrypt_symmetric_key(receiv_site: str, symm_key: bytes) -> dict:
    # Get receiver's pub key
    pub_filename = receiv_site + "_pub.pem"
    pub_outpath = os.path.join(pub_keys_path, pub_filename)

    if os.path.isfile(pub_outpath):
        with open(pub_outpath, "rb") as f:
            pub_receiv = ECC.import_key(f.read())

    ######### THIS IS NOT WORKING #######
    #########error message: ############
    # enc_symmetric_key = pub_receiv.encrypt(symm_key)#
    #                    ^^^^^^^^^^^^^^^^^^
    #AttributeError: 'EccKey' object has no attribute 'encrypt'#

    #it seems you can NOT encrypt with ECC using pycryptodome

    enc_symmetric_key = pub_receiv.encrypt(symm_key)
    enc_symmetric_key_b64 = b64encode(enc_symmetric_key)
    sidecar = {'encrypted_symmetric_key': enc_symmetric_key_b64}

    return sidecar

def decrypt_data():
    pass