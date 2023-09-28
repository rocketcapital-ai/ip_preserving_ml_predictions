import hashlib
import random
import base58
import datetime
from eth_account.messages import encode_defunct
import json
import os
import pandas as pd
import requests
import shutil
import time
import yaml
from brownie import accounts, web3, Messaging, network
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Callable
from web3 import types

CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
CFG_DIR = os.path.abspath('{}//..//..//cfg_files'.format(CURRENT_DIR))
with open("{}//cfg.yml".format(CFG_DIR), "r") as config_file:
    CFG = yaml.safe_load(config_file)

DATA_DIR = os.path.abspath('{}//..//..//..//{}'.format(CURRENT_DIR, CFG['DATA_DIR']))
ENCRYPTED_DATA_DIR = os.path.abspath('{}//..//..//..//{}'.format(CURRENT_DIR, CFG['DATA_ENCRYPTED']))
RETRIEVED_DIR = os.path.abspath('{}//..//..//..//{}'.format(CURRENT_DIR, CFG['RETRIEVED_DIR']))
DECRYPTED_RETRIEVED_DIR = os.path.abspath('{}//..//..//..//{}'.format(CURRENT_DIR, CFG['RETRIEVED_DECRYPTED']))
PRIVATE_KEY_PATH = os.path.abspath('{}//..//..//..//{}'.format(CURRENT_DIR, CFG['PRIVATE_KEY_PATH']))
PUBLIC_KEY_PATH = os.path.abspath('{}//..//..//..//{}'.format(CURRENT_DIR, CFG['PUBLIC_KEY_PATH']))

HASH_BUFFER_SIZE = 65536
JWT = CFG['PINATA']['JWT']


class MessageStatusType:
    PENDING = 0
    RESPONDED = 1
    CANCELLED = 2


class Message:
    def __init__(self, message: list):
        self.sender = message[0]
        self.receiver = message[1]
        self.file_reference = hash_to_cid(message[2])
        self.encrypted_symmetric_key = message[3]
        self.signed_hash = message[4]
        self.pid = message[5]
        self.mid = message[6]
        self.decrypted_symmetric_key = message[7]


class CompetitionParams:
    def __init__(self, address, submission_directory, encrypted_directory):
        self.address = address
        self.submission_directory = submission_directory
        self.encrypted_directory = encrypted_directory


def cid_to_hash(cid: str) -> str:
    """
    Convert base58 cid to hash.
    :param cid: Base58 cid.
    :return: Hex string of cid.
    """
    res = base58.b58decode(cid).hex()
    return res[4:]


def decimal_to_uint(decimal_value: Decimal or float or int, decimal_places=6) -> int:
    """
    Convert decimal value to unsigned int.
    :param decimal_value: Decimal value.
    :param decimal_places: Decimal places.
    :return: Unsigned integer representation of decimal value as int type.
    """
    return int(Decimal('{}e{}'.format(decimal_value, decimal_places)))


def decrypt_symmetric_key(private_key: RSA.RsaKey, encrypted_symmetric_key: bytes) -> bytes:
    """
    Decrypt symmetric key using private key.
    :param private_key: Private key as RSA.RsaKey. Must be the key pair of the public key used to encrypt the symmetric key.
    :param encrypted_symmetric_key: Encrypted symmetric key as bytes.
    :return: Decrypted symmetric key in bytes.
    """
    decrypt = PKCS1_OAEP.new(private_key)
    decrypted_key = decrypt.decrypt(encrypted_symmetric_key)
    return decrypted_key


def decrypt_file(retrieved_file_path: str, decryption_key: bytes, decrypted_file_name: str,
                 directory=DECRYPTED_RETRIEVED_DIR, file_ext="csv") -> str:
    """
    Decrypt file using symmetric key.
    :param retrieved_file_path: Path to encrypted file.
    :param decryption_key: Symmetric key as bytes.
    :param decrypted_file_name: Name of decrypted file.
    :param directory: Directory to save decrypted file.
    :param file_ext: File extension.
    :return: Path to decrypted file.
    """
    with open(retrieved_file_path, 'rb') as enc_f:
        key = enc_f.read()
    nonce = key[:16]
    ciphertext = key[16:-16]
    tag = key[-16:]
    cipher = AES.new(decryption_key, AES.MODE_GCM, nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    decrypted_file_path = f"{directory}/{decrypted_file_name}.{file_ext}"
    os.makedirs(directory, exist_ok=True)
    with open(decrypted_file_path, 'wb') as dec_f:
        dec_f.write(decrypted_data)
    return decrypted_file_path


def encrypt_csv(file_name: str,
                symmetric_key: bytes,
                submission_directory=DATA_DIR,
                encrypted_directory=ENCRYPTED_DATA_DIR) -> str:
    """
    Encrypt csv file using symmetric key.
    :param file_name: Name of csv file to encrypt.
    :param symmetric_key: Symmetric key as bytes.
    :param submission_directory: Directory where csv file is saved.
    :param encrypted_directory: Directory to save encrypted file.
    :return: Path to encrypted file.
    """
    if file_name.split('.')[-1] != 'csv':
        assert False, 'Please input a .csv file.'

    encrypted_file_name = '{}'.format(datetime.now().strftime('%Y-%m-%d_%Hh%Mm%Ss'))

    # Encrypt and save predictions file.
    cipher = AES.new(symmetric_key, AES.MODE_GCM)
    with open('{}//{}'.format(submission_directory, file_name), 'rb') as f:
        ciphertext, tag = cipher.encrypt_and_digest(f.read())
    os.makedirs(encrypted_directory, exist_ok=True)
    encrypted_file_path = '{}//{}.bin'.format(encrypted_directory, encrypted_file_name)
    with open(encrypted_file_path, 'wb') as new_encrypted_file:
        for x in (cipher.nonce, ciphertext, tag):
            new_encrypted_file.write(x)
    return encrypted_file_path


def encrypt_symmetric_key(public_key: RSA.RsaKey, symmetric_key: bytes) -> bytes:
    """
    Encrypt symmetric key using public key.
    :param public_key: Public key as RSA.RsaKey.
    :param symmetric_key: Symmetric key as bytes.
    :return: Encrypted symmetric key as bytes.
    """
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_symmetric_key = cipher.encrypt(symmetric_key)
    return encrypted_symmetric_key


def fr(sender):
    """
    Convenience wrapper for specifying transaction options when sending blockchain transactions.
    Modifiy this function to change default transaction options.
    :param sender: Address of sender.
    :return: Transaction options as dict.
    """
    return {"from": sender}


def generate_key_pair(name) -> RSA.RsaKey:
    """
    Generate public-private key pair.
    :param name: Identifier to save files as.
    :return: Public key as RSA.RsaKey.
    """
    from Crypto.PublicKey import RSA
    from pathlib import Path
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    private = private_key.export_key(pkcs=8).decode()
    public = public_key.export_key(pkcs=8).decode()
    # Don't overwrite private key if the key already exists.

    private_key_path = Path(f'{name}_private_key.pem')
    public_key_path = Path(f'{name}_public_key.pem')

    if private_key_path.exists() or public_key_path.exists():
        assert False, 'The public or private key already exists!'

    with open(private_key_path, 'w') as f:
        f.write(private)
        print('Private key saved to: {}'.format(private_key_path))

    with open(public_key_path, 'w') as f:
        f.write(public)
        print('Public key saved to: {}'.format(public_key_path))

    return public_key


def generate_symmetric_key() -> bytes:
    """
    Generate symmetric key randomly.
    :return: Symmetric key as bytes.
    """
    return get_random_bytes(16)


def hash_file(file_name: str, directory=DATA_DIR) -> str:
    """
    Hash file using SHA1.
    :param file_name: Name of file to hash.
    :param directory: Directory where file is located.
    :return: Hash of file as hex string.
    """
    sha1 = hashlib.sha1()

    with open(f"{directory}//{file_name}", 'rb') as f:
        while True:
            data = f.read(HASH_BUFFER_SIZE)
            if not data:
                break
            sha1.update(data)

    return sha1.hexdigest()


def hash_to_cid(hash_obj: bytes or bytearray or str) -> str:
    """
    Convert hash to base58 CID.
    :param hash_obj: Hash as bytes, bytearray, or hex string.
    :return: Hash as base58 CID.
    """
    if isinstance(hash_obj, (bytes, bytearray)): hash_obj = hash_obj.hex()
    hash_obj = '1220' + str(hash_obj)
    hash_obj = int(hash_obj, 16)
    return base58.b58encode_int(hash_obj).decode('utf-8')


def pin_file_to_ipfs(filename: str, jwt=JWT, cid_version=0, verbose=False, retry_seconds=3, num_retries=10) -> str:
    """
    Pin file to IPFS via Pinata API.
    :param filename: Name of file to pin.
    :param jwt: JWT for Pinata API.
    :param cid_version: CID version to use. Default is 0.
    :param verbose: Print verbose output.
    :param retry_seconds: Interval to wait before trying request again.
    :param num_retries: Number of times to retry request.
    :return: IPFS hash of pinned file.
    """
    url = '{}/{}'.format(CFG['IPFS_API_URL'], 'pinning/pinFileToIPFS')
    headers = {"Authorization": "Bearer " + jwt}
    for tries in range(num_retries):
        try:
            with open(filename, 'rb') as f:
                files = {"file": f}
                params = {"cidVersion": cid_version}
                response = requests.post(url, headers=headers, files=files, params=params)
                if verbose:
                    print('Pinned payload with size {} bytes to {} at {}.'.format(
                        response['PinSize'], response['IpfsHash'], response['Timestamp']))
                return response.json()['IpfsHash']
        except Exception as e:
            if tries == num_retries - 1:
                assert False, 'File could not be uploaded and pinned to IPFS.'
            time.sleep(retry_seconds)


def retrieve_content(cid, retry_seconds=3, num_retries=10):
    for tries in range(num_retries):
        try:
            requests.get('{}/{}'.format(CFG['IPFS_GATEWAY'], CFG['IPFS_DEFAULT']), timeout=CFG['REQUESTS_TIMEOUT'])
            r = requests.get('{}/{}'.format(CFG['IPFS_GATEWAY'], cid), timeout=CFG['REQUESTS_TIMEOUT'])
            return r.content
        except Exception as e:
            print(e)
            if tries == num_retries - 1:
                assert False, 'File could not be retrieved. Please try again later.'
            time.sleep(retry_seconds)


def retrieve_file(cid, directory=RETRIEVED_DIR, retry_seconds=3, num_retries=10):
    """
    Retrieve file from IPFS.
    :param cid: Base58 CID of file.
    :param directory: Directory to save file.
    :param retry_seconds: Interval to wait before trying request again.
    :param num_retries: Number of times to retry request.
    :return: Path to retrieved file.
    """
    content = retrieve_content(cid, retry_seconds, num_retries)
    os.makedirs(directory, exist_ok=True)
    file_path = f"{directory}/{cid}.bin"
    with open(file_path, 'wb') as f:
        f.write(content)
    return file_path


def rsa_export_hex(public_key: RSA.RsaKey) -> str:
    """
    Export public key as hex string.
    :param public_key: Public key as RSA.RsaKey.
    :return: Hex string of public key.
    """
    return public_key.export_key(format='DER', pkcs=8).hex()


def rsa_import_hex(hex_key: str) -> RSA.RsaKey:
    """
    Import key from hex string.
    :param hex_key: Hex string of key.
    :return: Key as RSA.RsaKey.
    """
    return RSA.import_key(hex_key)


def rsa_import_pem(file_path: str) -> RSA.RsaKey:
    """
    Import key from pem file.
    :param file_path: Path to pem file.
    :return: Key as RSA.RsaKey.
    """
    with open(file_path, 'rb') as f:
        key = RSA.import_key(f.read())
    return key


def sign_message(message: str, private_key: str) -> str:
    """
    Sign message using private key.
    :param message: Message string to sign.
    :param private_key: Private key as hex string.
    :return: Signature as hex string.
    """
    signed_message = web3.eth.account.sign_message(encode_defunct(text=message), private_key=private_key)
    return signed_message.signature.hex()


def verify_signature(message: str, signature: str, address: str) -> bool:
    """
    Verify signature of message.
    :param message: Message string to verify.
    :param signature: Signature as hex string.
    :param address: Address to verify against.
    :return: True if signature is valid, False otherwise.
    """
    try:
        recovered_address = web3.eth.account.recover_message(encode_defunct(text=message), signature=signature)
        return recovered_address.lower() == address.lower()
    except Exception as e:
        print(e)
        return False


# region: Logging Utilities
class Colours:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    ORANGE = '\033[33m'
    PURPLE = '\033[35m'
    YELLOW = '\033[93m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    WHITE = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BG = '\033[90m'


class LogType:
    DEFAULT = "DEFAULT"
    INFO = "INFO"
    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


def log(msg, log_type: LogType, verbose=True):
    if not verbose:
        return
    if log_type == LogType.INFO:
        color = Colours.OKBLUE
    elif log_type == LogType.WARNING:
        color = Colours.WARNING
    elif log_type == LogType.ERROR:
        color = Colours.ORANGE
    elif log_type == LogType.SUCCESS:
        color = Colours.OKGREEN
    elif log_type == LogType.DEFAULT:
        color = Colours.WHITE
    elif log_type == LogType.CRITICAL:
        color = Colours.FAIL
    else:
        raise Exception("Invalid log type.")
    timestamp, timestring = get_timestamp()
    log_msg = f"{color}{timestring} | {log_type} | {msg}{Colours.WHITE}"
    print(log_msg)

    return timestamp, timestring, msg


def get_timestamp() -> (int, str):
    current = datetime.now(timezone.utc)
    timestamp = int(current.timestamp() * 1000)
    timestring = current.strftime("%Y-%m-%d %H:%M:%S.%f")
    return timestamp, timestring
# endregion


# region: Development-only utilities
def generate_csv(num_rows=5, num_cols=5) -> str:
    _, timestring = get_timestamp()
    letters = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
               "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T",
               "U", "V", "W", "X", "Y", "Z"]
    arr = []
    for i in range(num_rows):
        asset = "".join(random.choices(letters, k=3))
        row = [asset]
        for j in range(num_cols):
            row.append(random.randint(1, 100))
        arr.append(row)
    cols = ["Asset"]
    for j in range(num_cols):
        cols.append(f"col_{j}")
    df = pd.DataFrame(arr, columns=cols)
    file_name = f"{timestring}.csv"
    df.to_csv(f"{DATA_DIR}//{file_name}", index=False)
    return file_name
# endregion
