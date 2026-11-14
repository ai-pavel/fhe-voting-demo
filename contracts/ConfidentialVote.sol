// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FHE, ebool, externalEbool} from "@fhevm/solidity/lib/FHE.sol";
import {EncryptedTally} from "./EncryptedTally.sol";

/// @title Confidential yes/no vote
/// @notice Individual votes are encrypted end-to-end. The contract tallies them homomorphically and
///         only the final totals are ever decrypted. Voters are identified by address: how they voted is
///         hidden, but who voted is public. See `AnonymousConfidentialVote` for a version that hides both.
contract ConfidentialVote is EncryptedTally {
    mapping(address voter => bool) public hasVoted;

    event Voted(address indexed voter);

    error AlreadyVoted();

    constructor(string memory proposal_, uint256 durationSeconds) EncryptedTally(proposal_, durationSeconds) {}

    /// @notice Cast an encrypted ballot: true = yes, false = no.
    /// @param encryptedSupport the encrypted ballot handle
    /// @param inputProof proof that the ciphertext is well-formed and bound to this contract and sender
    function vote(externalEbool encryptedSupport, bytes calldata inputProof) external whileOpen {
        if (hasVoted[msg.sender]) revert AlreadyVoted();
        hasVoted[msg.sender] = true;

        ebool support = FHE.fromExternal(encryptedSupport, inputProof);
        _addBallot(support);

        emit Voted(msg.sender);
    }
}
