#!/usr/bin/python3
import os
import datetime
import tarfile
from typing import IO
import nacl.utils
from nacl.encoding import Base64Encoder, RawEncoder
from nacl.public import PrivateKey, PublicKey, Box
from nacl.exceptions import CryptoError

# Main paths
project_root = os.path.dirname(os.path.dirname(__file__))
pub_keys_path = os.path.join(project_root, "keys", "public")
priv_keys_path = os.path.join(project_root, "keys", "private")
files_path = os.path.join(project_root, "files")

# Timestamp for filenames
dateTimeObj = datetime.datetime.now(tz=None)
timestamp = (
    str(dateTimeObj.year)
    + "-"
    + str(dateTimeObj.month)
    + "-"
    + str(dateTimeObj.day)
    + "_"
    + str(dateTimeObj.hour)
    + "-"
    + str(dateTimeObj.minute)
    + "-"
    + str(dateTimeObj.second)
)


def create_new_keypair(orig_site: str) -> IO:
    # Generate private key
    priv_key = PrivateKey.generate()
    # Generate matchig public key
    pub_key = priv_key.public_key

    # Base64 encoded keys
    priv_key_b64 = priv_key.encode(encoder=Base64Encoder).decode()
    pub_key_b64 = pub_key.encode(encoder=Base64Encoder).decode()

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
                f.write(priv_key_b64)
            print("File with private key for {}: {}".format(orig_site, priv_outpath))
        except OSError as err:
            print(
                "Could not write file with private key for {}: {}".format(
                    orig_site, err
                )
            )
    if not os.path.isfile(pub_outpath):
        try:
            with open(pub_outpath, "wt") as f:
                f.write(pub_key_b64)
        except OSError as err:
            print("Could not write public key file {}: {}".format(pub_outpath, err))


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


def create_archive(pt_id: str, orig_site: str, receiv_site: str) -> IO:
    # pt_id/to_receiv_site, pt_id/to_receiv_site/tmp are created by tf5t.py

    # Path to receiver's pt_id
    to_receiv_dir = os.path.join(files_path, pt_id, str("to_" + receiv_site))
    # Name from archive
    archive_filename = (
        pt_id + "_" + orig_site + "_" + receiv_site + "_" + timestamp + ".tar.gz"
    )
    # Path to temp directory for pt_id
    pt_id_tmp = os.path.join(to_receiv_dir, "tmp")
    # Output path
    archive_outpath = os.path.join(pt_id_tmp, archive_filename)

    # Function to exclude tmp subdirectory from compressed tarball
    def exclude_tmp(tarinfo):
        if "tmp" in tarinfo.name.split(os.sep):
            return None
        return tarinfo

    if not os.path.isfile(archive_outpath):
        try:
            with tarfile.open(archive_outpath, "x:gz") as tar:
                tar.add(
                    to_receiv_dir,
                    arcname=str(orig_site + "_" + receiv_site + "_" + pt_id),
                    filter=exclude_tmp,
                )
            print(
                "Created archive from {} to be sent to {}: {}".format(
                    orig_site, receiv_site, archive_outpath
                )
            )
        except OSError as err:
            print(
                "Failed to create archive from {} to be sent to {}: {}{}Error: {}".format(
                    orig_site, receiv_site, archive_outpath, "\n", err
                )
            )


def encrypt_archive(pt_id: str, orig_site: str, receiv_site: str) -> IO:
    priv_key_orig = import_priv_key(orig_site)
    pub_key_receiv = import_pub_key(receiv_site)

    # Box with the private key from original site
    # and the receiver's public key
    # Generates shared key = symmetric key encryption
    orig_box = Box(priv_key_orig, pub_key_receiv)

    # Path to archive from origin site
    archive_filename = (
        pt_id + "_" + orig_site + "_" + receiv_site + "_" + timestamp + ".tar.gz"
    )
    pt_id_tmp = os.path.join(files_path, pt_id, str("to_" + receiv_site), "tmp")
    archive_path = os.path.join(pt_id_tmp, archive_filename)

    # Try to open and read archive as binary
    if os.path.isfile(archive_path):
        try:
            with open(archive_path, "rb") as f:
                archive = f.read()

            # Random nonce automatically generated with encrypt()
            # Symmetric/shared key + nonce + archive encrypted with XSalsa20
            # Poly1305 authentication tag preprended to the ciphertext
            # enc_archive contains the ciphertext along with the authentication info
            # and the nonce used for this encryption
            # Encrypted archive will be exactly 40 bytes longer than the original archive
            enc_archive = orig_box.encrypt(archive)

            enc_archive_filename = (
                pt_id
                + "_"
                + orig_site
                + "_"
                + receiv_site
                + "_"
                + timestamp
                + ".enc"
            )
            enc_archive_path = os.path.join(pt_id_tmp, enc_archive_filename)

            if not os.path.isfile(enc_archive_path):
                try:
                    with open(enc_archive_path, "wb") as f:
                        f.write(enc_archive)
                    print(
                        "Encrypted archive for {} from {} to be sent to {}: {}".format(
                            pt_id, orig_site, receiv_site, enc_archive_path
                        )
                    )
                except OSError as err:
                    print(
                        "Failed to encrypt archive for {} from {} to be sent to {}: {}{}Error: {}".format(
                            pt_id, orig_site, receiv_site, enc_archive_path, "\n", err
                        )
                    )
        except OSError as err:
            print("Could not open archive {}: {}".format(archive_path, err))


def decrypt_archive(pt_id: str, orig_site: str, receiv_site: str) -> IO:
    priv_key_receiv = import_priv_key(receiv_site)
    pub_key_orig = import_pub_key(orig_site)

    # Box with the private key from the receiver site
    # and the public key from the origin site
    receiv_box = Box(priv_key_receiv, pub_key_orig)

    # Path to encrypted archive from origin site
    to_receiv_dir = os.path.join(files_path, pt_id, str("to_" + receiv_site))
    pt_id_temp = os.path.join(to_receiv_dir, "tmp")
    enc_archive_filename = (
        pt_id + "_" + orig_site + "_" + receiv_site + "_" + timestamp + ".enc"
    )
    enc_archive_path = os.path.join(pt_id_temp, enc_archive_filename)

    # Open and decrypt archive

    if os.path.isfile(enc_archive_path):
        try:
            with open(enc_archive_path, "rb") as f:
                enc_archive = f.read()
            # Decrypted archive
            # Decryption with omitted nonce (encrypted with ciphertext)
            # and the shared key
            dec_archive = receiv_box.decrypt(enc_archive)

            # Path to receiver's decrypted archive (.tar.gz)
            dec_archive_filename = (
                pt_id
                + "_"
                + orig_site
                + "_"
                + receiv_site
                + "_"
                + timestamp
                + ".dec.tar.gz"
            )
            dec_archive_path = os.path.join(to_receiv_dir, dec_archive_filename)

            if not os.path.isfile(dec_archive_path):
                try:
                    with open(dec_archive_path, "wb") as f:
                        f.write(dec_archive)
                    print(
                        "Decrypted archive for {} from {} to {}: {}".format(
                            pt_id, orig_site, receiv_site, dec_archive_path
                        )
                    )
                except OSError as err:
                    print(
                        "Failed to create decrypted archive for {} from {} to be sent to {}: {}{}Error: {}".format(
                            pt_id, orig_site, receiv_site, enc_archive_path, "\n", err
                        )
                    )
        except OSError as err:
            print(
                "Failed to open encrypted archive {}: {}".format(enc_archive_path, err)
            )


def unpack_archive(pt_id: str, orig_site: str, receiv_site: str) -> IO:
    # Path to receiver's decrypted archive (.tar.gz)
    to_receiv_dir = os.path.join(files_path, pt_id, str("to_" + receiv_site))
    dec_archive_filename = (
        pt_id + "_" + orig_site + "_" + receiv_site + "_" + timestamp + ".dec.tar.gz"
    )
    dec_archive_path = os.path.join(to_receiv_dir, dec_archive_filename)

    unpacked_archive_path = os.path.join(
        to_receiv_dir, str(orig_site + "_" + receiv_site + "_" + pt_id)
    )

    if os.path.isfile(dec_archive_path):
        try:
            with tarfile.open(dec_archive_path, "r:gz") as tar:
                tar.extractall(path=to_receiv_dir)
            print(
                "Unpacked archive from {} sent to {}: {}".format(
                    orig_site, receiv_site, unpacked_archive_path
                )
            )
        except OSError as err:
            print(
                "Failed to open archive from {} sent to {}: {}{}Error: {}".format(
                    orig_site, receiv_site, dec_archive_path, "\n", err
                )
            )