pragma solidity ^0.8.20;

contract attestation {
    address public owner;
    string[] public MREnclaveList;
    string[] public MRSignerList;
    uint[] public UpdateBlockNumber;

    constructor(address _owner) {
        owner = _owner;
    }

    modifier onlyOwner {    
        require(msg.sender == owner);
        _;
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