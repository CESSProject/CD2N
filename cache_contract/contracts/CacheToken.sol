pragma solidity ^0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract CacheToken is ERC721 {

    address owner;

    mapping(uint256 => uint256) public releaseTime;

    event MintToken(address indexed owner, uint256 indexed tokenId);

    constructor(string memory name_, string memory symbol_) ERC721(name_, symbol_) {
        owner = msg.sender;
    }

    function mintToken(address to) public payable {
        require(msg.value >= 100000000000000000000, "Insufficient payment");
        if (to == address(0)) {
            revert ERC721InvalidReceiver(address(0));
        }

        uint256 tokenId = _generateToken();

        address previousOwner = _update(to, tokenId, address(0));

        if (previousOwner != address(0)) {
            revert ERC721InvalidSender(address(0));
        }

        releaseTime[tokenId] = block.timestamp + 300;

        emit MintToken(to, tokenId);
    }

    function withdraw() external {
        require(owner == msg.sender, "Error Caller");

        payable(owner).transfer(address(this).balance);
    }

    function _generateToken() private view returns (uint256) {
        return uint256(keccak256(abi.encode(block.timestamp)));
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public virtual override {
        _checkTokenIdLock(tokenId);
        transferFrom(from, to, tokenId);
        _checkERC721Received(from, to, tokenId, data);
    }

    function transferFrom(address from, address to, uint256 tokenId) public virtual override {
         _checkTokenIdLock(tokenId);
        if (to == address(0)) {
            revert ERC721InvalidReceiver(address(0));
        }
        // Setting an "auth" arguments enables the `_isAuthorized` check which verifies that the token exists
        // (from != 0). Therefore, it is not needed to verify that the return value is not 0 here.
        address previousOwner = _update(to, tokenId, _msgSender());
        if (previousOwner != from) {
            revert ERC721IncorrectOwner(from, tokenId, previousOwner);
        }
    }

    /**
     * @dev Private function to invoke {IERC721Receiver-onERC721Received} on a target address. This will revert if the
     * recipient doesn't accept the token transfer. The call is not executed if the target address is not a contract.
     *
     * @param from address representing the previous owner of the given token ID
     * @param to target address that will receive the tokens
     * @param tokenId uint256 ID of the token to be transferred
     * @param data bytes optional data to send along with the call
     */ 
    function _checkERC721Received(address from, address to, uint256 tokenId, bytes memory data) private {
        if (to.code.length > 0) {
            try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, data) returns (bytes4 retval) {
                if (retval != IERC721Receiver.onERC721Received.selector) {
                    revert ERC721InvalidReceiver(to);
                }
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert ERC721InvalidReceiver(to);
                } else {
                    /// @solidity memory-safe-assembly
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        }
    }

    function _checkTokenIdLock(uint256 tokenId) private view {
        require(block.timestamp > releaseTime[tokenId], "The token is locked");
    }
}