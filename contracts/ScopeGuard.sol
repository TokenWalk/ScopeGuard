// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.6;

import "@gnosis.pm/safe-contracts/contracts/base/GuardManager.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@gnosis.pm/safe-contracts/contracts/interfaces/IERC165.sol";
import "@gnosis/zodiac/contracts/core/FactoryFriendly.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

abstract contract BaseGuard is Guard {
    function supportsInterface(bytes4 interfaceId)
        external
        view
        virtual
        returns (bool)
    {
        return
            interfaceId == type(Guard).interfaceId || // 0xe6d7a83a
            interfaceId == type(IERC165).interfaceId; // 0x01ffc9a7
    }
}

contract ScopeGuard is FactoryFriendly, OwnableUpgradeable, BaseGuard {
    event TargetAllowed(address target);
    event TargetDisallowed(address target);
    event FunctionAllowedOnTarget(address target, bytes4 functionSig);
    event FunctionDisallowedOnTarget(address target, bytes4 functionSig);
    event ParameterAllowedOnFunction(
        address target,
        bytes4 functionSig,
        bytes32 parameterHash
    );
    event ParameterDisallowedOnFunction(
        address target,
        bytes4 functionSig,
        bytes32 parameterHash
    );
    event TargetScoped(address target, bool scoped);
    event FunctionScoped(address target, bytes4 functionSig, bool scoped);
    event DelegateCallsAllowedOnTarget(address target);
    event DelegateCallsDisallowedOnTarget(address target);
    event ScopeGuardSetup(address indexed initiator, address indexed owner);

    constructor(address _owner) {
        bytes memory initializeParams = abi.encode(_owner);
        setUp(initializeParams);
    }

    /// @dev Initialize function, will be triggered when a new proxy is deployed
    /// @param initializeParams Parameters of initialization encoded
    function setUp(bytes memory initializeParams) public override {
        require(!initialized, "Guard is already initialized");
        address _owner = abi.decode(initializeParams, (address));

        if (_owner != address(0)) {
            __Ownable_init();
            transferOwnership(_owner);
            initialized = true;
            emit ScopeGuardSetup(msg.sender, _owner);
        }
    }

    struct Function {
        bool allowed;
        bool scoped;
        bool delegateCallAllowed;
        mapping(bytes32 => bool) allowedParameters;
    }

    struct Target {
        bool allowed;
        bool scoped;
        bool delegateCallAllowed; // maybe unnecessary
        mapping(bytes4 => Function) allowedFunctions;
    }

    mapping(address => Target) public allowedTargets;

    /// @dev Allows multisig owners to make call to an address.
    /// @notice Only callable by owner.
    /// @param target Address to be allowed.
    function allowTarget(address target) public onlyOwner {
        allowedTargets[target].allowed = true;
        emit TargetAllowed(target);
    }

    /// @dev Disallows multisig owners to make call to an address.
    /// @notice Only callable by owner.
    /// @param target Address to be disallowed.
    function disallowTarget(address target) public onlyOwner {
        allowedTargets[target].allowed = false;
        emit TargetDisallowed(target);
    }

    /// @dev Allows multisig owners to call specific function on a scoped address.
    /// @notice Only callable by owner.
    /// @param target Address that the function should be allowed.
    /// @param functionSig Function signature to be allowed.
    function allowFunction(address target, bytes4 functionSig)
        public
        onlyOwner
    {
        allowedTargets[target].allowedFunctions[functionSig].allowed = true;
        emit FunctionAllowedOnTarget(target, functionSig);
    }

    /// @dev Disallows multisig owners to call specific function on a scoped address.
    /// @notice Only callable by owner.
    /// @param target Address that the function should be disallowed.
    /// @param functionSig Function signature to be disallowed.
    function disallowFunction(address target, bytes4 functionSig)
        public
        onlyOwner
    {
        allowedTargets[target].allowedFunctions[functionSig].allowed = false;
        emit FunctionDisallowedOnTarget(target, functionSig);
    }

    /// @dev Allows multisig owners to make delegate calls to an address.
    /// @notice Only callable by owner.
    /// @param target Address to which delegate calls will be allowed.
    function allowDelegateCall(address target) public onlyOwner {
        allowedTargets[target].delegateCallAllowed = true;
        emit DelegateCallsAllowedOnTarget(target);
    }

    /// @dev Disallows multisig owners to make delegate calls to an address.
    /// @notice Only callable by owner.
    /// @param target Address to which delegate calls will be disallowed.
    function disallowDelegateCall(address target) public onlyOwner {
        allowedTargets[target].delegateCallAllowed = false;
        emit DelegateCallsDisallowedOnTarget(target);
    }

    /// @dev Sets whether or not calls to an address should be scoped to specific function signatures.
    /// @notice Only callable by owner.
    /// @param target Address that will be scoped/unscoped.
    function toggleTargetScoped(address target) public onlyOwner {
        allowedTargets[target].scoped = !allowedTargets[target].scoped;
        emit TargetScoped(target, allowedTargets[target].scoped);
    }

    /// @dev Sets whether or not calls to an address and function should be scoped to specific parameters.
    /// @notice Only callable by owner.
    /// @param target Address that will be scoped/unscoped.
    function toggleFunctionScoped(address target, bytes4 functionSig)
        public
        onlyOwner
    {
        allowedTargets[target]
            .allowedFunctions[functionSig]
            .scoped = !allowedTargets[target]
            .allowedFunctions[functionSig]
            .scoped;
        emit FunctionScoped(
            target,
            functionSig,
            allowedTargets[target].allowedFunctions[functionSig].scoped
        );
    }

    /// @dev Allows multisig owners to call specific paramters on a scoped address and function.
    /// @notice Only callable by owner.
    /// @param target Address that the function should be allowed.
    /// @param functionSig Function signature to be allowed.
    /// @param dataHash Hash of the calldata containing allowed parameters
    function allowParameters(
        address target,
        bytes4 functionSig,
        bytes32 dataHash
    ) public onlyOwner {
        allowedTargets[target].allowedFunctions[functionSig].allowedParameters[
                dataHash
            ] = true;
        emit ParameterAllowedOnFunction(target, functionSig, dataHash);
    }

    /// @dev Disallows multisig owners to call specific parameters on a scoped address.
    /// @notice Only callable by owner.
    /// @param target Address that the function should be disallowed.
    /// @param functionSig Function signature to be disallowed.
    /// @param dataHash Hash of the calldata containing disallowed parameters
    function disallowParameters(
        address target,
        bytes4 functionSig,
        bytes32 dataHash
    ) public onlyOwner {
        allowedTargets[target].allowedFunctions[functionSig].allowedParameters[
                dataHash
            ] = false;
        emit ParameterDisallowedOnFunction(target, functionSig, dataHash);
    }

    /// @dev Returns bool to indicate if an address is an allowed target.
    /// @param target Address to check.
    function isAllowedTarget(address target) public view returns (bool) {
        return (allowedTargets[target].allowed);
    }

    /// @dev Returns bool to indicate if a function signature is allowed for a target address.
    /// @param target Address to check.
    /// @param functionSig Signature to check.
    function isAllowedFunction(address target, bytes4 functionSig)
        public
        view
        returns (bool)
    {
        return (allowedTargets[target].allowedFunctions[functionSig].allowed);
    }

    /// @dev Returns bool to indicate if parameters are allowed for a target address and function.
    /// @param target Address to check.
    /// @param functionSig Signature to check.
    /// @param dataHash Hash of calldata containg parameters to check
    function isAllowedParameters(
        address target,
        bytes4 functionSig,
        bytes32 dataHash
    ) public view returns (bool) {
        return (allowedTargets[target]
            .allowedFunctions[functionSig]
            .allowedParameters[dataHash] == true);
    }

    /// @dev Returns bool to indicate if an address is scoped.
    /// @param target Address to check.
    function isTargetScoped(address target) public view returns (bool) {
        return (allowedTargets[target].scoped);
    }

    /// @dev Returns bool to indicate if an address is scoped.
    /// @param target Address to check.
    function isFunctionScoped(address target, bytes4 functionSig)
        public
        view
        returns (bool)
    {
        return (allowedTargets[target].allowedFunctions[functionSig].scoped);
    }

    /// @dev Returns bool to indicate if delegate calls are allowed to a target address.
    /// @param target Address to check.
    function isAllowedToDelegateCall(address target)
        public
        view
        returns (bool)
    {
        return (allowedTargets[target].delegateCallAllowed);
    }

    // solhint-disallow-next-line payable-fallback
    fallback() external {
        // We don't revert on fallback to avoid issues in case of a Safe upgrade
        // E.g. The expected check method might change and then the Safe would be locked.
    }

    function checkTransaction(
        address to,
        uint256,
        bytes memory data,
        Enum.Operation operation,
        uint256,
        uint256,
        uint256,
        address,
        // solhint-disallow-next-line no-unused-vars
        address payable,
        bytes memory,
        address
    ) external view override {
        bool targetScoped = allowedTargets[to].scoped;
        bool functionScoped = allowedTargets[to]
            .allowedFunctions[bytes4(data)]
            .scoped;
        require(
            operation != Enum.Operation.DelegateCall ||
                allowedTargets[to].delegateCallAllowed,
            "Delegate call not allowed to this address"
        );
        require(isAllowedTarget(to), "Target address is not allowed");
        if (data.length >= 4) {
            require(
                !targetScoped || isAllowedFunction(to, bytes4(data)),
                "Target function is not allowed"
            );
            require(
                !functionScoped ||
                    isAllowedParameters(to, bytes4(data), keccak256(data)),
                "Cannot send with these parameters"
            );
        } else {
            require(
                !targetScoped || isAllowedFunction(to, bytes4(0)),
                "Cannot send to this address"
            );
        }
    }

    function checkAfterExecution(bytes32, bool) external view override {}
}
