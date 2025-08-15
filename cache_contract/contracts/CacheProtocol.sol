pragma solidity ^0.8.20;

import {CacheToken} from "./CacheToken.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract CacheProtocol is Ownable {
    address peerId;

    uint256 createTime;

    uint256 nodeNum;

    uint256 public UnitPrice;

    uint256 CurTotalTraffic;

    uint256 TotalCollerate;

    mapping( address => uint256 ) public TrafficNum;

    mapping( uint256 => uint256 ) public TermTotalTraffic;

    mapping( address => NodeInfo ) public Node;

    mapping( uint256 => bool ) public TokenBonded;

    mapping( address => mapping ( address => uint256 )) public UserTrafficMap;

    address[] public TeeNodes;

    struct NodeInfo {
        bool created;
        uint256 collerate;
        uint256 tokenId;
        string endpoint;
        address teeEth;
        bytes teeCess;
    }

    mapping(address => uint256) public CacheReward;

    mapping(address => uint256) public RewardRecord;

    mapping(bytes32 => OrderInfo) public Order;

    struct OrderInfo {
        uint256 value;
        address creater;
        address node;
        uint256 term;
    }

    string[] public MREnclaveList;

    string[] public MRSignerList;

    uint[] public UpdateBlockNumber;

    event Staking(address indexed nodeAcc, uint256 indexed tokenId);

    event OrderPayment(address indexed teeAcc, uint256 traffic);

    event TrafficForwarding(address indexed nodeAcc, uint256 traffic);

    event Claim(address indexed nodeAcc, uint256 reward);

    event Exit(address indexed nodeAcc);

    constructor(address peerid, address _owner) Ownable(_owner) {
        peerId = peerid;
        createTime = block.timestamp;
        UnitPrice = 1192092895;
    }

    function updateUnitPrice(uint256 _price) external {
        _checkOwner();

        UnitPrice = _price;
    }

    function isTokenOwner(address acc, uint256 tokenId) public view returns (bool) {
        address _owner = CacheToken(peerId).ownerOf(tokenId);

        return (_owner == acc);
    }

    function staking(address nodeAcc, address tokenAcc, uint256 tokenId, string memory _endpoint, bytes memory _signature, address _teeEth, bytes memory _teeCess) external payable {   
        if (isTokenOwner(tokenAcc, tokenId) == false) {
            revert("Not the token holder");
        }

        bytes32 _msgHash = getMessageHash(nodeAcc, tokenId);
        bytes32 msgHash = toEthSignedMessageHash(_msgHash);
        if (verify(msgHash, _signature, tokenAcc) == false) {
            revert("verify signature failed");
        }

        Node[nodeAcc] = NodeInfo(true, msg.value, tokenId, _endpoint, _teeEth, _teeCess);
        if (_teeEth != address(0)) {
            TeeNodes.push(_teeEth);
        }
        TrafficNum[nodeAcc] = 0;
        CacheReward[nodeAcc] = 0;
        RewardRecord[nodeAcc] = 0;
        TotalCollerate += msg.value;
        TokenBonded[tokenId] = true;
        nodeNum += 1;

        emit Staking(nodeAcc, tokenId);
    }

    function removeTeeNodes(uint i) internal {
        TeeNodes[i] = TeeNodes[TeeNodes.length - 1];
        TeeNodes.pop();
    }

    function cacheOrderPayment(address _teeAcc, uint256 _traffic) external payable {
        if (msg.value != _traffic * UnitPrice) {
            revert("Insufficient amount");
        }

        UserTrafficMap[msg.sender][_teeAcc] += _traffic;

        emit OrderPayment(_teeAcc, _traffic);
    }

    function trafficForwarding(address user, address _nodeAcc, uint256 _traffic) external {
        uint256 term = getCurrencyTerm();

        UserTrafficMap[user][msg.sender] -= _traffic;
        TrafficNum[_nodeAcc] += _traffic;

        if (TermTotalTraffic[term] == 0) {
            TermTotalTraffic[term] = TermTotalTraffic[term] + _traffic + CurTotalTraffic;
        } else {
            TermTotalTraffic[term] += _traffic;
        }

        CurTotalTraffic += _traffic;

        CacheReward[_nodeAcc] = _traffic * UnitPrice;

        emit TrafficForwarding(_nodeAcc, _traffic);
    }

    function claim() external {
        uint256 term = getCurrencyTerm();
        require(RewardRecord[msg.sender] < term - 1, "Please wait until the next term to claim the reward");

        NodeInfo memory _nodeInfo = Node[msg.sender];
        require(_nodeInfo.created, "Cache node not registered");

        uint256 alpha = _getAlpha();

        uint256 totalOrderNum = nodeNum + TermTotalTraffic[term - 1];

        uint256 avg = nodeNum / totalOrderNum;

        uint256 numOrder = TrafficNum[msg.sender];

        uint256 rewardWord = CacheReward[msg.sender];

        uint256 rewardTerm = (
            ((avg + (alpha * (numOrder - avg))) / totalOrderNum * 2 / 10)
        ) * 100000000000000000000000;
            
        uint256 issueReward = (rewardWord + rewardTerm) * 40 / 100;

        CacheReward[msg.sender] = rewardWord + rewardTerm - issueReward;

        payable(msg.sender).transfer(issueReward);
        RewardRecord[msg.sender] = term - 1;
        TrafficNum[msg.sender] = 0;
        CurTotalTraffic -= numOrder;

        emit Claim(msg.sender, issueReward);
    }

    function exit() external {
        NodeInfo memory _nodeInfo = Node[msg.sender];
        require(_nodeInfo.created, "Cache node not registered");

        payable(msg.sender).transfer(_nodeInfo.collerate);
        if (_nodeInfo.teeEth != address(0)) {
            uint16 i;
            for (i = 0; i <= TeeNodes.length; i++) {
                if (TeeNodes[i] == _nodeInfo.teeEth) {
                    removeTeeNodes(i);
                }
            }
        }

        CurTotalTraffic -= TrafficNum[msg.sender];
        delete TrafficNum[msg.sender];
        delete Node[msg.sender];
        delete RewardRecord[msg.sender];
        delete CacheReward[msg.sender];
        delete TokenBonded[_nodeInfo.tokenId];

        emit Exit(msg.sender);
    }

    function _generateOrderId(address nodeAcc) private view returns (bytes32) {
        return keccak256(abi.encodePacked(block.timestamp, nodeAcc));
    }

    function _getAlpha() private view returns (uint256) {
        if (2000 + (38 * getCurrencyTerm()) < 6000) {
            return (2000 + (38 * getCurrencyTerm()));
        } else {
            return 6000;
        }
    }

    function recoverSigner(bytes32 _msgHash, bytes memory _signature) public pure returns (address) {
        require(_signature.length == 65, "invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := byte(0, mload(add(_signature, 0x60)))
        }
        return ecrecover(_msgHash, v, r, s);
    }

    function openRecover(bytes32 _msgHash, bytes memory _signature) public view returns (address) {
        address signer = ECDSA.recover(_msgHash, _signature);
        require(signer != address(0), "ECDSA: invalid signature");
        require(signer == msg.sender, "MyFunction: invalid signature");

        return signer;
    }

    function verify(bytes32 _msgHash, bytes memory _signature, address _signer) public pure returns (bool) {
        return recoverSigner(_msgHash, _signature) == _signer;
    }

    function toEthSignedMessageHash(bytes32 hash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
    
    function getMessageHash(address _account, uint256 _tokenId) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_account, _tokenId));
    }

    function getCurrencyTerm() public view returns (uint256) {
        return ((block.timestamp - createTime) / 604800);
    }

    function addMREnclave (string memory value) external onlyOwner {
        MREnclaveList.push(value);
        UpdateBlockNumber.push(block.number);
    }

    function addMRSigner (string memory value) external onlyOwner {
        MRSignerList.push(value);
    }

    function getAllMREnclaveList() external view returns (string[] memory) {
        return MREnclaveList;
    }

    function getAllUpdateBlockNumber() external view returns (uint[] memory) {
        return UpdateBlockNumber;
    }

    function getAllMRSignerList() external view returns (string[] memory) {
        return MRSignerList;
    }
}