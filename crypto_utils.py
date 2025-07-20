"""
crypto_utils.py
Cryptographic utilities for password manager: key derivation (Argon2) and AES-GCM encryption/decryption.
"""
import os
from typing import Tuple
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants for Argon2 parameters
ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 2 ** 16  # 64 MiB
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a symmetric encryption key from the master password using Argon2id.
    Args:
        password (str): Master password.
        salt (bytes): Random salt.
    Returns:
        bytes: Derived key.
    """
    # Argon2id for strong password-based key derivation
    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID
    )
    return key


def generate_salt() -> bytes:
    """
    Generate a secure random salt for key derivation.
    Returns:
        bytes: Random salt.
    """
    return os.urandom(ARGON2_SALT_LEN)


def encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt data using AES-GCM.
    Args:
        plaintext (bytes): Data to encrypt.
        key (bytes): Symmetric key.
    Returns:
        Tuple[bytes, bytes]: (nonce, ciphertext_with_tag)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt data using AES-GCM.
    Args:
        nonce (bytes): Nonce used during encryption.
        ciphertext (bytes): Encrypted data with tag.
        key (bytes): Symmetric key.
    Returns:
        bytes: Decrypted plaintext.
    Raises:
        Exception: If decryption fails (e.g., wrong key or corrupted data).
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None) 