from .core_tools.tools import *


class Receiver:
    def __init__(self, account: network.account.Account, msg_contract_address: str, private_key_path=PRIVATE_KEY_PATH, file_ext="csv"):
        self.__private_key = None
        self.pkp = private_key_path
        self.load_private_key(private_key_path)
        self.__file_ext = file_ext
        self.msg = Messaging.at(msg_contract_address)
        self.account = account
        self.waiting_on_response_from = []

    def load_private_key(self, private_key_path=PRIVATE_KEY_PATH):
        """
        Loads the private key from the specified path.
        :param private_key_path: Path to private key.
        :return: None
        """
        self.__private_key = rsa_import_pem(private_key_path)

    def get_messages(self, msg_type=MessageStatusType.PENDING) -> [Message]:
        """
        Retrieve messages intended for this receiver.
        :param msg_type: Type of message to retrieve - types found here: `MessageStatusType`.
        :return: List of messages as `Message` objects.
        """
        messages = self.msg.getMessages(self.account.address, msg_type, 0, 0)
        return list(map(lambda x: Message(x), messages))

    def get_earliest_message(self, msg_type=MessageStatusType.PENDING) -> Message or None:
        """
        Retrieve the earliest message intended for this receiver.
        :param msg_type: Type of message to retrieve - types found here: `MessageStatusType`.
        :return: `Message` object.
        """
        messages = self.get_messages(msg_type)
        if len(messages) == 0:
            return None
        return messages[0]

    def set_own_public_key(self, public_key_path=PUBLIC_KEY_PATH):
        """
        Set the public key of this receiver.
        :param public_key_path: Path to .pem file for this account's public key.
        :return: None
        """
        pub_key_hex = rsa_export_hex(rsa_import_pem(public_key_path))
        self.msg.setPublicKey(pub_key_hex, fr(self.account))
        log(f"Public key set for {self.account.address}.", LogType.INFO)

    def retrieve_message(self, sender: str, file_reference: str, encrypted_symmetric_key: bytes,
                         signature: str, verbose=True) -> str or None:
        """

        :param sender: Address of message sender.
        :param file_reference: File reference in base58 CID format.
        :param encrypted_symmetric_key: Encrypted symmetric key in bytes.
        :param signature: Signature of original, unencrypted file signed with sender's private key.
        :param verbose: Set to True to print status messages.
        :return: Path of decrypted file. None if signature verification fails.
        """

        log(f"Retrieving message from sender: {sender}.", LogType.INFO, verbose)

        retrieved_file_path = retrieve_file(file_reference)
        log(f"File {file_reference} retrieved from IPFS.", LogType.DEFAULT, verbose)

        print("pkp", self.pkp)
        symmetric_key = decrypt_symmetric_key(self.__private_key, encrypted_symmetric_key)
        log(f"Symmetric key decrypted.", LogType.DEFAULT, verbose)

        file_path = decrypt_file(retrieved_file_path, symmetric_key, file_reference, DECRYPTED_RETRIEVED_DIR, self.__file_ext)
        log(f"File decrypted to {file_path}.", LogType.DEFAULT, verbose)

        file_hash = hash_file(f"{file_reference}.{self.__file_ext}", DECRYPTED_RETRIEVED_DIR)
        log(f"File hashed.", LogType.DEFAULT, verbose)

        verified = verify_signature(file_hash, signature, sender)
        if verified:
            log(f"Signature verified for {sender}. Message retrieval completed.", LogType.SUCCESS, verbose)
            return file_path
        else:
            log(f"Signature verification failed for {sender}. Message retrieval failed.", LogType.ERROR, verbose)
            return None

    def get_response_message(self, request_id):
        response_id = self.msg.requestResponse(request_id)
        if response_id == 0:
            return None
        response_message = self.msg.messages(response_id)
        return Message(response_message)
