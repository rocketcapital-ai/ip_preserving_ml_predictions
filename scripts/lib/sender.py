from .core_tools.tools import *


class Sender:
    def __init__(self, account: network.account.Account, msg_contract_address: str):
        self.account = account
        self.msg = Messaging.at(msg_contract_address)
        self.unresponded_requests = []

    def get_public_key(self, receiver_address: str) -> RSA.RsaKey:
        """
        Retrieve the public key of the specified receiver.
        :param receiver_address: Address of receiver.
        :return: Public key of receiver in RSA.RsaKey format.
        """
        return rsa_import_hex(self.msg.publicKeys(receiver_address))

    def send_request(self, receiver_address: str, file_reference: str, encrypted_symmetric_key: bytes, signature: str):
        """
        Sends a request message to the smart contract.
        :param receiver_address: Address of receiver.
        :param file_reference: File reference in base58 CID format.
        :param encrypted_symmetric_key: Encrypted symmetric key in bytes.
        :param signature: Signature of original, unencrypted file signed with sender's private key.
        :return: None
        """
        file_reference = cid_to_hash(file_reference)
        tx = self.msg.request(receiver_address, file_reference, encrypted_symmetric_key, signature, fr(self.account))
        msg_id = tx.events['Request']['msgId']
        self.unresponded_requests.append(msg_id)
        log_msg = f"Request sent to {receiver_address}. Message ID: {1}."
        log(log_msg, LogType.INFO)
        log_msg = f"\nFile reference: {file_reference}"
        log_msg += f"\nEncrypted symmetric key: {encrypted_symmetric_key.hex()}"
        log_msg += f"\nSignature: {signature}"
        log(log_msg, LogType.DEFAULT)
        return tx

    def send_response(self, receiver_address: str, file_reference: str, encrypted_symmetric_key: bytes, signature: str, pid: int):
        """
        Sends a response message to the smart contract.
        :param receiver_address: Address of receiver.
        :param file_reference: File reference in base58 CID format.
        :param encrypted_symmetric_key: Encrypted symmetric key in bytes.
        :param signature: Signature of original, unencrypted file signed with sender's private key.
        :param pid: Message ID of the request message being responded to, as int.
        :return: None
        """
        file_reference = cid_to_hash(file_reference)
        self.msg.respond(receiver_address, file_reference, encrypted_symmetric_key, signature, pid, fr(self.account))
        log_msg = f"Response sent to {receiver_address} for message ID {pid}."
        log(log_msg, LogType.INFO)
        log_msg = f"\nFile reference: {file_reference}"
        log_msg += f"\nEncrypted symmetric key: {encrypted_symmetric_key.hex()}"
        log_msg += f"\nSignature: {signature}"
        log(log_msg, LogType.DEFAULT)

    def prepare_message(self, file_name: str, public_key: RSA.RsaKey, verbose=True) -> tuple:
        """
        Uploads the file to IPFS and prepares the message to be sent to the smart contract.
        :param file_name: Name of file to send.
        :param public_key: Public key of receiver.
        :param verbose: Set to True to print status messages.
        :return: Tuple of file reference in base58 CID format, encrypted symmetric key, signature and symmetric key.
        """
        log(f"Preparing message for file: {file_name}.", LogType.INFO, verbose)

        symmetric_key = generate_symmetric_key()
        log(f"Symmetric key generated.", LogType.DEFAULT, verbose)

        encrypted_file_path = encrypt_csv(file_name, symmetric_key)
        log(f"File encrypted to {encrypted_file_path}.", LogType.DEFAULT, verbose)

        file_reference = pin_file_to_ipfs(encrypted_file_path)
        log(f"File pinned to IPFS with reference: {file_reference}.", LogType.DEFAULT, verbose)

        encrypted_symmetric_key = encrypt_symmetric_key(public_key, symmetric_key)
        log(f"Symmetric key encrypted.", LogType.DEFAULT, verbose)

        file_hash = hash_file(file_name, DATA_DIR)
        log(f"File hashed.", LogType.DEFAULT, verbose)

        signature = sign_message(file_hash, self.account.private_key)
        log(f"Signature generated", LogType.DEFAULT, verbose)

        log(f"Message preparation completed.", LogType.INFO, verbose)

        return file_reference, encrypted_symmetric_key, signature, symmetric_key

    def publish_symmetric_key(self, msg_id: int, symmetric_key: bytes):
        """
        Publishes the symmetric key linked to the specified message ID.
        :param msg_id: Message ID this symmetric key is meant for.
        :param symmetric_key: Unencrypted symmetric key in bytes.
        :return: None
        """
        self.msg.updateDecryptedSymmetricKey(msg_id, symmetric_key, fr(self.account))
        log(f"Symmetric key published for message ID {msg_id}.", LogType.INFO)




