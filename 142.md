ctf_sec

medium

# Swivel lending function missing slippage check in Lender.sol

## Summary

Swivel lending function missing slippage check in Lender.sol

## Vulnerability Detail

The rest of lending function in Lender.sol not including the Swivel lending function implementation the slippage check.

Let us use Tempus lending function as a example, in the end, if the received amount less than slippage limit, the transaction revert

```solidity
  // Calculate the amount of Tempus principal tokens received after the deposit
  uint256 received = IERC20(principal).balanceOf(address(this)) - start;

  // Verify that a minimum number of principal tokens were received
  if (received < r) {
      revert Exception(11, received, r, address(0), address(0));
  }
```

However, the same slippage check is missing in Swivel lending function is missing,

the parameter premiumSlippage only applies if the e flag is on

```solidity
    /// @param e flag to indicate if returned funds should be swapped in Yield Space Pool
    /// @param premiumSlippage slippage limit, minimum amount to PTs to buy
```

the slippage check does not applies how many tokens the smart contract received.

```solidity
    // Compute how many principal tokens were received
    received =
        IERC20(IMarketPlace(marketPlace).token(u, m, p)).balanceOf(
            address(this)
        ) -
        startingZcTokens;
}

// Mint Illuminate principal tokens to the user
IERC5095(principalToken(u, m)).authMint(msg.sender, received);
```

## Impact

User can suffer from slippage and return unexpectedly small number of minted principal token.

## Code Snippet

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L413-L436

## Tool used

Manual Review

## Recommendation

We recommend the project add the slippage check to validate the minimum amount of token minted after lending from Swivel satisfy user's slippage limit.
