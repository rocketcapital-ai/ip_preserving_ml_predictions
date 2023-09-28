pragma solidity ^0.8.0;

import "OpenZeppelin/openzeppelin-contracts@4.8.0/contracts/utils/structs/EnumerableSet.sol";
import "./AccessControlMsg.sol";

contract Messaging is AccessControlMsg {

    using EnumerableSet for EnumerableSet.UintSet;
    
    enum MessageStatusType { Pending, Responded, Cancelled }
    
    struct Message {
        address sender;
        address receiver;
        bytes32 fileReference;
        bytes encryptedSymmetricKey;
        bytes signedHash;
        uint256 pid;
        uint256 mid;
        bytes decryptedSymmetricKey;
    }
    
    mapping(address => bytes) public publicKeys;
    mapping(uint256 => Message) public messages;
    mapping(uint256 => uint256) public requestResponse;
    uint256 public counter;
    mapping(address => EnumerableSet.UintSet) internal pendingIds;
    mapping(address => EnumerableSet.UintSet) internal respondedIds;
    mapping(address => EnumerableSet.UintSet) internal cancelledIds;
    
    event Request(uint256 indexed msgId, address indexed sender, address indexed receiver);
    event Response(uint256 indexed msgId, uint256 indexed pid , address indexed sender, address receiver);
    event SymmetricKeyUpdated(uint256 indexed msgId, bytes symmetricKey);
    event PublicKeyUpdated(address indexed sender, bytes publicKey);

    constructor() {
        counter = 1;
        _initializeRciAdmin(msg.sender);
    }

    function setPublicKey(bytes calldata publicKey) external {
        publicKeys[msg.sender] = publicKey;
        emit PublicKeyUpdated(msg.sender, publicKey);
    }
    
    function request(
        address receiver, 
        bytes32 fileReference, 
        bytes calldata encryptedSymmetricKey,
        bytes calldata signedHash
    )
    external
    onlyRole(REQUESTER)
    returns (uint256 messageId)
    {
        messageId = _createMessage(
            msg.sender,
            receiver,
            fileReference,
            encryptedSymmetricKey,
            signedHash,
            0
        );
        emit Request(counter - 1, msg.sender, receiver);
    }
    
    function respond(
        address receiver, 
        bytes32 fileReference, 
        bytes calldata encryptedSymmetricKey,
        bytes calldata signedHash,
        uint256 pid
    )
    external
    returns (uint256 messageId)
    {
        messageId = _createMessage(
            msg.sender,
            receiver,
            fileReference,
            encryptedSymmetricKey,
            signedHash,
            pid
        );
        emit Response(counter - 1, pid, msg.sender, receiver);
    }

    function updateDecryptedSymmetricKey(uint256 msgId, bytes calldata decryptedSymmetricKey)
    external
    {
        require(msg.sender == messages[msgId].sender);
        messages[msgId].decryptedSymmetricKey = decryptedSymmetricKey;
        emit SymmetricKeyUpdated(msgId, decryptedSymmetricKey);
    }

    function getPendingIds(address user) external view returns (uint256[] memory) {
        return _getListFromSet(pendingIds[user], 0, pendingIds[user].length());
    }

    function getIdLength(address user, MessageStatusType messageStatusType) 
    external view 
    returns (uint256) 
    {
        if (messageStatusType == MessageStatusType.Pending) {
            return pendingIds[user].length();
        } 
        else if (messageStatusType == MessageStatusType.Responded) {
            return respondedIds[user].length();
        }
    
        return cancelledIds[user].length();
    }

    function getMessages(address user, MessageStatusType messageStatusType, uint256 startIndex, uint256 endIndex)
    external view
    returns (Message[] memory messageList)
    {
        if (messageStatusType == MessageStatusType.Pending) {
            if ((endIndex == 0) || (endIndex > pendingIds[user].length())) {
                endIndex = pendingIds[user].length();
            }
            messageList = _getMessages(user, _getListFromSet(pendingIds[user], startIndex, endIndex));
        }
        else if (messageStatusType == MessageStatusType.Responded) {
            if ((endIndex == 0) || (endIndex > respondedIds[user].length())) {
                endIndex = respondedIds[user].length();
            }
            messageList = _getMessages(user, _getListFromSet(respondedIds[user], startIndex, endIndex));
        }
        else {
            if ((endIndex == 0) || (endIndex > cancelledIds[user].length())) {
                endIndex = cancelledIds[user].length();
            }
            messageList = _getMessages(user, _getListFromSet(cancelledIds[user], startIndex, endIndex));
        }
    }

    function _createMessage(
        address sender,
        address receiver, 
        bytes32 fileReference, 
        bytes calldata encryptedSymmetricKey,
        bytes calldata signedHash,
        uint256 pid
    )
    internal
    returns (uint256 messageId)
    {
        require(sender != receiver, "Sender and receiver cannot be the same");
        messages[counter] = Message(
            sender,
            receiver,
            fileReference,
            encryptedSymmetricKey,
            signedHash,
            pid,
            counter,
            ""
        );
        
        // Request
        if (pid == 0) {
            pendingIds[receiver].add(counter);
        }
        // Response
        else {
            require(sender == messages[pid].receiver, "Sender must be the same as the receiver of the request");
            require(receiver == messages[pid].sender, "Receiver must be the same as the sender of the request");
            require(pendingIds[sender].contains(pid), "No such pending request.");
            pendingIds[sender].remove(pid);
            requestResponse[pid] = counter;
            if (uint(fileReference) == 0) {
                cancelledIds[receiver].add(pid);
            } else {
                respondedIds[receiver].add(pid);
            }
        }
        messageId = counter;
        counter++;
    }

    function _getMessages(address user, uint256[] memory ids)
    internal view
    returns (Message[] memory messageList)
    {
        messageList = new Message[](ids.length);
        for (uint i = 0; i < ids.length; i++) {
            messageList[i] = messages[ids[i]];
        }
    }
    
    function _getListFromSet(EnumerableSet.UintSet storage setOfData, uint256 startIndex, uint256 endIndex)
    internal view
    returns (uint256[] memory listOfData)
    {
        listOfData = new uint256[](endIndex - startIndex);
        for (uint i = startIndex; i < endIndex; i++){
            listOfData[i - startIndex] = setOfData.at(i);
        }
    }
}