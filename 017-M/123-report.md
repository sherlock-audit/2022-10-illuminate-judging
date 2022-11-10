hansfriese

high

# `Redeemer.autoRedeem()` checks the allowance incorrectly.

## Summary
`Redeemer.autoRedeem()` checks the allowance incorrectly.

## Vulnerability Detail
The `autoRedeem()` function is used to redeem the principal token by third parties.

```solidity
    // Loop through the provided arrays and mature each individual position
    for (uint256 i; i != length; ) {
        // Fetch the allowance set by the holder of the principal tokens
        uint256 allowance = uToken.allowance(f[i], address(this)); //@audit wrong token & don't decrease allowance

        // Get the amount of tokens held by the owner
        uint256 amount = pt.balanceOf(f[i]);

        // Calculate how many tokens the user should receive
        uint256 redeemed = (amount * holdings[u][m]) / pt.totalSupply();

        // Calculate the fees to be received (currently .025%)
        uint256 fee = redeemed / feenominator;

        // Verify allowance
        if (allowance < amount) {
            revert Exception(20, allowance, amount, address(0), address(0));
        }

        // Burn the tokens from the user
        pt.authBurn(f[i], amount);
```

This function checks the allowance for the redeemer contract because it can be called by anyone.

As we can confirm [from the comment](https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L511), it should be an allowance of the principal token because it burns the principal token from the owner.

Also, the allowance should be decreased after the burning, otherwise, the allowance can be used again and again.

It's possible when the owner has another balance from someone after he's auto-redeemed and the callers can auto-redeem him again with the already used allowance and charge the incentive.

## Impact
Currently, it checks the allowance of the wrong token so that `autoRedeem()` wouldn't work as expected.

Also, it doesn't decrease the allowance after the auto burning so that the owner might be auto-redeemed more than he has allowed.

## Code Snippet
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L511-L525

## Tool used
Manual Review

## Recommendation
Recommend modifying [the allowance calculation](https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L511) like below.

```solidity
    uint256 allowance = pt.allowance(f[i], address(this));
```

Also consider decreasing the allowance after burning.