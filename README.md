# Introduction
We are pleased to announce that Rocket Capital Investment has been awarded the Monetary Authority of Singapore’s Financial Sector Technology and Innovation (FSTI) Proof of Concept (POC) grant! 
The FSTI POC grant provides funding support for experimentation, development, and dissemination of nascent innovative technologies in the financial services sector!

In this repository you can find the paper, code and documentation for the POC.

## Paper
The paper can be found [here](https://docs.google.com/viewer?url=https://github.com/rocketcapital-ai/ip_preserving_ml_predictions/blob/main/IP-PRESERVING-ML-PREDICTIONS.pdf).


# Implementation
## Documentation
A full description of this implementation can be found [here](https://github.com/rocketcapital-ai/ip_preserving_ml_predictions/blob/main/docs/Implementation.pdf).


## Setup

This project uses the [`eth-brownie`](https://eth-brownie.readthedocs.io/en/stable/) framework for interacting and/or simulating blockchain interactions.

### Install dependencies
```bash
pip install -r requirements.txt
```

### Create or import wallets into brownie.
```bash
brownie accounts generate <account_name>
```
or
 ```bash
 brownie accounts new <account_name>
 ```

### Running the development script
You will need to populate the entries in `main.py` inside the arrow brackets with the appropriate values. These specify the name of your brownie wallet created above, as well as the path to the public and private key `.pem` files.

If needed, generate keys via the `generate_key_pair` function in `core_tools/tools.py`.

You will need 2 accounts, 1 for the user making the request and 1 for the user responding to the request. Accordingly, you will also need 2 sets of public-private key pairs.

This script uses IPFS via the Pinata API. Obtain a JWT from [Pinata](https://pinata.cloud/) and paste it into the `JWT` field in the `cfg.yml` file.

Then, run:
```bash
brownie run scripts/main.py -I
```
(`-I` flag is for interactive mode, which allows you to interact with the blockchain after the script is run.)

This script makes 1 iteration of the messaging protocol. 

#### Send Request
- A generates a request (a csv file) and a symmetric key.
- A encrypts the request with the symmetric key and pins it to IPFS, obtaining a file reference.
- A encrypts the symmetric key with B's public key.
- A hashes the request, and signs this hash with A's private key.
- A register the file reference to the encrypted request, the encrypted symmetric key and the signature, along with B's wallet address as a REQUEST on the `Messaging` smart contract.

#### Receive Request
- B checks the `Messaging` smart contract for pending requests.
- B retrieves the file reference to the encrypted request, the encrypted symmetric key and the signature from the `Messaging` smart contract.
- B decrypts the symmetric key with B's private key.
- B retrieves the encrypted request from IPFS using the file reference.
- B decrypts the request with the symmetric key.
- B hashes the request and verifies the signature with A's wallet address.

#### Send Response
- B generates a response (a csv file) and a symmetric key.
- B encrypts the response with the symmetric key and pins it to IPFS, obtaining a file reference.
- B encrypts the symmetric key with A's public key.
- B hashes the response, and signs this hash with B's private key.
- B registers the file reference to the encrypted response, the encrypted symmetric key and the signature, along with A's wallet address and the message id of the original REQUEST from A as a RESPONSE on the `Messaging` smart contract.

#### Receive Response
- A checks the `Messaging` smart contract for pending responses to the original REQUEST.
- A retrieves the file reference to the encrypted response, the encrypted symmetric key and the signature from the `Messaging` smart contract.
- A decrypts the symmetric key with A's private key.
- A retrieves the encrypted response from IPFS using the file reference.
- A decrypts the response with the symmetric key.
- A hashes the response and verifies the signature with B's wallet address.

#### Publishing Symmetric Encryption Keys
- A and B both publish their unencrypted symmetric keys for the request and response respectively to the `Messaging` smart contract. This is to demonstrate the ability to allow any member of the public to verify the contents of the original request and original response at a later time.


