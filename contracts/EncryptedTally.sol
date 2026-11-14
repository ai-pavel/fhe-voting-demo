// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FHE, ebool, euint32} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

/// @title Encrypted yes/no tally
/// @notice Shared FHE core of the voting contracts: ballots are added homomorphically to two encrypted counters,
///         and only the final totals are ever decrypted (publicly, after the deadline, via the Zama KMS).
/// @dev Subcontracts decide who may vote and call `_addBallot` with an already-validated `ebool`. Because the
///      ballot type is `ebool`, a voter cannot stuff the box with Enc(1000): its value is guaranteed to be 0 or 1.
abstract contract EncryptedTally is ZamaEthereumConfig {
    string public proposal;
    uint256 public immutable deadline;

    euint32 private _yesVotes;
    euint32 private _noVotes;

    uint32 public voterCount;

    bool public tallyRequested;
    bool public tallyRevealed;
    uint32 public yesResult;
    uint32 public noResult;

    event TallyRequested(bytes32 yesHandle, bytes32 noHandle);
    event TallyRevealed(uint32 yes, uint32 no);

    error VotingClosed();
    error VotingStillOpen();
    error TallyAlreadyRequested();
    error TallyNotRequested();
    error TallyAlreadyRevealed();

    constructor(string memory proposal_, uint256 durationSeconds) {
        proposal = proposal_;
        deadline = block.timestamp + durationSeconds;

        _yesVotes = FHE.asEuint32(0);
        _noVotes = FHE.asEuint32(0);
        FHE.allowThis(_yesVotes);
        FHE.allowThis(_noVotes);
    }

    modifier whileOpen() {
        if (block.timestamp >= deadline) revert VotingClosed();
        _;
    }

    /// @dev yes += support; no += !support — both counters change, so observers can't tell which one moved.
    function _addBallot(ebool support) internal {
        voterCount++;
        _yesVotes = FHE.add(_yesVotes, FHE.asEuint32(support));
        _noVotes = FHE.add(_noVotes, FHE.asEuint32(FHE.not(support)));
        FHE.allowThis(_yesVotes);
        FHE.allowThis(_noVotes);
    }

    /// @notice After the deadline, anyone can mark the two totals as publicly decryptable.
    ///         Individual ballots are never made decryptable.
    function requestTally() external {
        if (block.timestamp < deadline) revert VotingStillOpen();
        if (tallyRequested) revert TallyAlreadyRequested();
        tallyRequested = true;

        FHE.makePubliclyDecryptable(_yesVotes);
        FHE.makePubliclyDecryptable(_noVotes);

        emit TallyRequested(FHE.toBytes32(_yesVotes), FHE.toBytes32(_noVotes));
    }

    /// @notice Submit the KMS-signed cleartext totals. Anyone can call this; forged values are rejected
    ///         because the KMS threshold signatures are verified on-chain.
    /// @param abiEncodedClearValues abi.encode(uint32 yes, uint32 no) as returned by the relayer
    /// @param decryptionProof KMS signatures over the handles and cleartexts
    function revealTally(bytes calldata abiEncodedClearValues, bytes calldata decryptionProof) external {
        if (!tallyRequested) revert TallyNotRequested();
        if (tallyRevealed) revert TallyAlreadyRevealed();

        bytes32[] memory handles = new bytes32[](2);
        handles[0] = FHE.toBytes32(_yesVotes);
        handles[1] = FHE.toBytes32(_noVotes);
        FHE.checkSignatures(handles, abiEncodedClearValues, decryptionProof);

        (yesResult, noResult) = abi.decode(abiEncodedClearValues, (uint32, uint32));
        tallyRevealed = true;

        emit TallyRevealed(yesResult, noResult);
    }

    /// @notice Encrypted running totals (opaque handles; decryptable only after `requestTally`).
    function getEncryptedTally() external view returns (euint32 yes, euint32 no) {
        return (_yesVotes, _noVotes);
    }
}
