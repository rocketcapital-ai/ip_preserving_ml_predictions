from scripts.lib.message_user import *

ITERATIONS = 10


def main():
    # setup
    admin = accounts.load("<account_name_0>")
    msg = Messaging.deploy(fr(admin))

    # specify here for development purposes. Otherwise use the yml configuration file.
    requester_keys = {
        "public": "<path_to_public_key_0>",
        "private": "<path_to_private_key_0>"
    }
    responder_keys = {
        "public": "<path_to_public_key_1>",
        "private": "<path_to_private_key_1>"
    }

    requester = MessageUser("<account_name_0>", msg.address, requester_keys["private"])
    responder = MessageUser("<account_name_1>", msg.address, responder_keys["private"])

    requester.receiver.set_own_public_key(requester_keys["public"])
    responder.receiver.set_own_public_key(responder_keys["public"])

    for _ in range(ITERATIONS):
        # Request
        csv_name = generate_csv()
        df = pd.read_csv(f"{DATA_DIR}//{csv_name}")
        log(f"Request Dataset. {df}", LogType.INFO, True)
        public_key = requester.sender.get_public_key(responder.address)
        file_reference, encrypted_symmetric_key, signature, requester_symmetric_key = requester.sender.prepare_message(csv_name, public_key)
        requester.sender.send_request(
            responder.address,
            file_reference,
            encrypted_symmetric_key,
            signature)

        # Request made. Responder polls for requests.
        while (m := responder.receiver.get_earliest_message()) is None:
            pass

        decrypted_file_path = responder.receiver.retrieve_message(
            m.sender,
            m.file_reference,
            m.encrypted_symmetric_key,
            m.signed_hash,
        )

        df = pd.read_csv(decrypted_file_path)
        log(f"Received Dataset. {df}", LogType.INFO, True)

        # # Response
        csv_name = generate_csv()
        df = pd.read_csv(f"{DATA_DIR}//{csv_name}")
        log(f"Response File. {df}", LogType.INFO, True)
        public_key = responder.sender.get_public_key(requester.address)
        file_reference, encrypted_symmetric_key, signature, responder_symmetric_key = responder.sender.prepare_message(csv_name, public_key)
        responder.sender.send_response(
            requester.address,
            file_reference,
            encrypted_symmetric_key,
            signature,
            m.mid
        )

        while (m_response := requester.receiver.get_response_message(requester.sender.unresponded_requests[-1])) is None:
            pass
        requester.sender.unresponded_requests.pop(-1)

        decrypted_file_path = requester.receiver.retrieve_message(
            m_response.sender,
            m_response.file_reference,
            m_response.encrypted_symmetric_key,
            m_response.signed_hash,
        )

        df = pd.read_csv(decrypted_file_path)
        log(f"Received Response File. {df}", LogType.INFO, True)

        # Publish Symmetric Keys
        requester.sender.publish_symmetric_key(m.mid, requester_symmetric_key)
        responder.sender.publish_symmetric_key(m_response.mid, responder_symmetric_key)