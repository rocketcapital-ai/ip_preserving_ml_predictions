from scripts.lib.sender import *
from scripts.lib.receiver import *


class MessageUser:
    def __init__(self, wallet_name: str, msg_contract_address: str, private_key_path=PRIVATE_KEY_PATH, file_ext="csv"):
        self.account = accounts.load(wallet_name)
        self.sender = Sender(self.account, msg_contract_address)
        self.receiver = Receiver(self.account, msg_contract_address, private_key_path, file_ext)
        self.address = self.sender.account.address
