#!/usr/bin/python3
import os
import tarfile
from typing import IO
import nacl.utils
from nacl.hash import blake2b
from nacl.encoding import Base64Encoder, RawEncoder
from nacl.public import PrivateKey, PublicKey, Box
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox

project_root = os.path.dirname(os.path.dirname(__file__))
pub_keys_path = os.path.join(project_root, "keys", "public")
priv_keys_path = os.path.join(project_root, "keys", "private")
files_path = os.path.join(project_root, "files")

def create_new_keypair(orig_site: str) -> IO:

    # Generate private key
    priv_key = PrivateKey.generate()
    # Generate matchig public key
    pub_key = priv_key.public_key

    # Base64 encoded keys
    priv_key_b64 = priv_key.encode(encoder=Base64Encoder)
    pub_key_b64 = pub_key.encode(encoder=Base64Encoder)

    # Decode base64 keys to UTF-8 for file writing
    priv_key_b64_utf_8 = priv_key_b64.decode("utf-8")
    pub_key_b64_utf_8 = pub_key_b64.decode("utf-8")

    # Filename for a site's private key
    priv_filename = orig_site + ".priv"
    # Output path to a site's private key
    priv_outpath = os.path.join(priv_keys_path, priv_filename)
    # Filename for a site's public key
    pub_filename = orig_site + ".pub"
    # Output path to a site's public key
    pub_outpath = os.path.join(pub_keys_path, pub_filename)    

    # If files don't exist, try to write them
    if not os.path.isfile(priv_outpath):
        try:
            with open(priv_outpath, "wt") as f:
                f.write(priv_key_b64_utf_8)
            print("File with private key for {}: {}".format(orig_site,priv_outpath))
        except OSError as err:
            print("Could not write file with private key for {}: {}".format(orig_site, err))
    if not os.path.isfile(pub_outpath):
        try:
            with open(pub_outpath, "wt") as f:
                f.write(pub_key_b64_utf_8)
        except OSError as err:
            print("Could not write public key file {}: {}".format(pub_outpath,err))
                
def import_priv_key(orig_site: str) -> bytes:
    # Filename for a site's private key
    priv_filename = orig_site + ".priv"
    # Path to a site's private key
    priv_path = os.path.join(priv_keys_path, priv_filename)

    # Try to read file and return private key in bytes

    if os.path.isfile(priv_path):
        try:
            with open(priv_path, "r") as f:
                priv_key_b64_utf_8 = f.read()
            priv_key_b64_bytes = bytes(priv_key_b64_utf_8, "utf-8")
            priv_key = PrivateKey(priv_key_b64_bytes, encoder=Base64Encoder)    

            return priv_key     

        except OSError as err:
            print("Could not open {}: {}".format(priv_path, err))

def import_pub_key(receiv_site: str) -> bytes:
    # Filename for a site's public key
    pub_filename = receiv_site + ".pub"
    # Path to a site's private key
    pub_path = os.path.join(pub_keys_path, pub_filename)

    # Try to read file and return public key in bytes

    if os.path.isfile(pub_path):
        try:
            with open(pub_path, "r") as f:
                pub_key_b64_utf_8 = f.read()
            pub_key_b64_bytes = bytes(pub_key_b64_utf_8, "utf-8")
            pub_key = PublicKey(pub_key_b64_bytes, encoder=Base64Encoder)    

            return pub_key     

        except OSError as err:
            print("Could not open {}: {}".format(pub_path, err))

def create_archive(uid: str, orig_site: str, receiv_site: str) -> IO:
    #uid/to_receiv_site, uid/to_receiv_site/tmp are created by tf5t.py

    # Path to receiver's uid
    to_receiv_dir = os.path.join(files_path, uid, str("to_" + receiv_site))
    # Name from archive
    archive_filename = orig_site + "_" + receiv_site + "_" + uid + ".tar.gz"
    # Path to temp directory for uid
    uid_tmp = os.path.join(to_receiv_dir, "tmp")
    # Output path
    archive_outpath = os.path.join(uid_tmp, archive_filename)

    # Function to exclude tmp subdirectory from compressed tarball
    def exclude_tmp(tarinfo):
        if "tmp" in tarinfo.name.split(os.sep):
            return None
        return tarinfo

    if not os.path.isfile(archive_outpath):
        try:
            with tarfile.open(archive_outpath, "x:gz") as tar:
                tar.add(to_receiv_dir, arcname="", filter=exclude_tmp)
            print("Created archive from {} to be sent to {}: {}".format(orig_site,receiv_site,archive_outpath))
        except OSError as err:
            print("Failed to create archive from {} to be sent to {}: {}{}Error: {}".format(orig_site,receiv_site,archive_outpath,"\n",err))

# Maybe depricated if we need to stick to XSalsa20-Poly1305 
def encrypt_archive(uid: str, orig_site: str, receiv_site: str) -> IO:
    priv_key_orig = import_priv_key(orig_site)
    pub_key_receiv = import_pub_key(receiv_site)

    # Box with the private key from original site
    # and the receiver's public key
    orig_box = Box(priv_key_orig, pub_key_receiv)

    # Path to archive from origin site
    archive_filename = orig_site + "_" + receiv_site + "_" + uid + ".tar.gz"
    uid_tmp = os.path.join(files_path, uid, str("to_" + receiv_site), "tmp")
    archive_path = os.path.join(uid_tmp, archive_filename)

    # Try to open and read archive as binary
    if os.path.isfile(archive_path):
        try:
            with open(archive_path, "rb") as f:
                archive = f.read()

            # Encrypt archive (the "message"), which will be exactly 40 bytes
            # longer tha  the original archive  
            # The encrypted variable contains the ciphertext along with the authentication info
            # and the nonce used for this encryption
            enc_archive = orig_box.encrypt(archive)

            enc_archive_filename = orig_site + "_" + receiv_site + "_" + uid + ".enc"
            enc_archive_path = os.path.join(uid_tmp,enc_archive_filename)

            if not os.path.isfile(enc_archive_path):
                try:
                    with open(enc_archive_path, "wb") as f:
                        f.write(enc_archive)
                    print("Successfully encrypted archive for {} from {} to be sent to {}: {}".format(uid,orig_site,receiv_site,enc_archive_path))
                except OSError as err:
                    print("Failed to encrypt archive for {} from {} to be sent to {}: {}{}Error: {}".format(uid,orig_site,receiv_site,enc_archive_path,"\n",err))
        except OSError as err:
            print("Could not open archive {}: {}".format(archive_path,err))


def blake2b_encrypt_archive(uid: str, orig_site: str, receiv_site: str) -> IO | str:
    priv_key_orig = import_priv_key(orig_site)
    pub_key_receiv = import_pub_key(receiv_site)

    # Path to archive from origin site
    archive_filename = orig_site + "_" + receiv_site + "_" + uid + ".tar.gz"
    uid_tmp = os.path.join(files_path, uid, str("to_" + receiv_site), "tmp")
    archive_path = os.path.join(uid_tmp, archive_filename)

    # Box with the private key from original site
    # and the receiver's public key
    orig_box = Box(priv_key_orig, pub_key_receiv)
    # Shared key derived from priv_key_orig + pub_key_receiv
    # Identical to priv_key_receiv + pub_key_orig
    shared_key = orig_box.shared_key()

    # blake2b algorithm used to replace a key derivation function
    master_key = shared_key
    derivation_salt = nacl.utils.random(16)
    symmetric_key = blake2b(b'', key=master_key, salt=derivation_salt,
                            encoder=RawEncoder)
    
    # Create a SecretBox instance with the derived symmetric key
    secret_box = SecretBox(symmetric_key)

    # Generate a random nonce (use a secure random generator)
    nonce = nacl.utils.random(SecretBox.NONCE_SIZE)
    
    # Try to open and read archive as binary
    if os.path.isfile(archive_path):
        try:
            with open(archive_path, "rb") as f:
                archive = f.read()       

            # Encrypt the archive using the SecretBox
            # Does so using XSalsa20-Poly1305
            enc_archive = secret_box.encrypt(archive, nonce)
            
            enc_archive_filename = orig_site + "_" + receiv_site + "_" + uid + ".enc.tar.gz"
            enc_archive_path = os.path.join(uid_tmp,enc_archive_filename)

            if not os.path.isfile(enc_archive_path):
                try:
                    with open(enc_archive_path, "wb") as f:
                        f.write(enc_archive)
                    print("Successfully encrypted archive for {} from {} to be sent to {}: {}".format(uid,orig_site,receiv_site,enc_archive_path))


                    # Encode/Decode and return nonce and derivation_salt, as needed in json file for decryption
                    nonce_b64 = Base64Encoder.encode(nonce)
                    derivation_salt_b64 = Base64Encoder.encode(derivation_salt)
                    nonce_b64_utf_8 = nonce_b64.decode("utf-8")
                    derivation_salt_b64_utf_8 = derivation_salt_b64.decode("utf-8")
                    
                    return nonce_b64_utf_8,derivation_salt_b64_utf_8
                
                except OSError as err:
                    print("Failed to encrypt archive for {} from {} to be sent to {}: {}{}Error: {}".format(uid,orig_site,receiv_site,enc_archive_path,"\n",err))
        except OSError as err:
            print("Could not open archive {}: {}".format(archive_path,err))

def encrypt_archive_new(uid: str, orig_site: str, receiv_site: str) -> IO:
    pass
    # priv_key_orig = import_priv_key(orig_site)
    # pub_key_receiv = import_pub_key(receiv_site)

    # # This must be kept secret, this is the combination to your safe
    # key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    # print("Key:", key)

    # # This is your safe, you can use it to encrypt or decrypt messages
    # box = nacl.secret.SecretBox(key)

    # # Path to archive from origin site
    # archive_filename = orig_site + "_" + receiv_site + "_" + uid + ".tar.gz"
    # uid_tmp = os.path.join(files_path, uid, str("to_" + receiv_site), "tmp")
    # archive_path = os.path.join(uid_tmp, archive_filename)

    # # Try to open and read archive as binary
    # if os.path.isfile(archive_path):
    #     try:
    #         with open(archive_path, "rb") as f:
    #             archive = f.read()
            
    #         nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    #         encrypted = box.encrypt(archive, nonce)
    #         assert len(encrypted) == len(archive) + box.NONCE_SIZE + box.MACBYTES

    #     except OSError as err:
    #         print("Could not open archive {}: {}".format(archive_path,err))

# create_new_keypair("CGN")
# create_new_keypair("DRE")
# create_archive("patient1", "DRE", "CGN")
nonce,derivation_salt = blake2b_encrypt_archive("patient1", "DRE", "CGN")


def decrypt_archive(uid: str, orig_site: str, receiv_site: str) -> IO:
    priv_key_receiv = import_priv_key(receiv_site)
    pub_key_orig = import_pub_key(orig_site)

    # Box with the private key from the receiver site
    # and the public key from the origin site
    receiv_box = Box(priv_key_receiv, pub_key_orig)

    # Path to encrypted archive from origin site 
    to_receiv_dir = os.path.join(files_path, uid, str("to_" + receiv_site))
    uid_temp = os.path.join(to_receiv_dir, "tmp")
    enc_archive_filename = orig_site + "_" + receiv_site + "_" + uid + ".enc"
    enc_archive_path = os.path.join(uid_temp,enc_archive_filename)   

    # Decrypt archive

    if os.path.isfile(enc_archive_path):
        try:
            with open(enc_archive_path, "rb") as f:
                enc_archive = f.read()
            # Decrypted archive
            dec_archive = receiv_box.decrypt(enc_archive)

            # Path to receiver's decrypted archive (.tar.gz)
            dec_archive_filename = orig_site + "_" + receiv_site + "_" + uid + ".dec.tar.gz"
            dec_archive_path = os.path.join(to_receiv_dir,dec_archive_filename)

            if not os.path.isfile(dec_archive_path):
                try:
                    with open(dec_archive_path, "wb") as f:
                        f.write(dec_archive)
                    print("Successfully decrypted archive for {} from {} to {}: {}".format(uid,orig_site,receiv_site,dec_archive_path))
                except OSError as err:
                    print("Failed to create decrypted archive for {} from {} to be sent to {}: {}{}Error: {}".format(uid,orig_site,receiv_site,enc_archive_path,"\n",err))
        except OSError as err:
            print("Failed to open encrypted archive {}: {}".format(enc_archive_path,err))

def decrompress_archive(uid: str, orig_site: str, receiv_site: str) -> IO:
    pass