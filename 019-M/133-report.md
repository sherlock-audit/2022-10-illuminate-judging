ctf_sec

medium

# Compound Redeem may fail silently in Converter.sol

## Summary

Compound Redeem may fail silently in Converter.sol

## Vulnerability Detail

Converter is used to in Redeemer.sol

Redeem for Sense

```solidity
// Get the compounding token that is redeemed by Sense
address compounding = ISenseAdapter(a).target();

// Redeem the compounding token back to the underlying
IConverter(converter).convert(
    compounding,
    u,
    IERC20(compounding).balanceOf(address(this))
);
```

Redeem for Apwine

```solidity
// Convert the interest bearing token to underlying
IConverter(converter).convert(
    IAPWineFutureVault(futureVault).getIBTAddress(),
    u,
    IERC20(ibt).balanceOf(address(this))
);
```

Redeem for Pendle

```solidity
// Redeem the tokens from the Pendle contract
IPendle(pendleAddr).redeemAfterExpiry(forgeId, u, maturity);

// Get the compounding asset for this market
address compounding = IPendleToken(principal)
.underlyingYieldToken();

// Redeem the compounding to token to the underlying
IConverter(converter).convert(
compounding,
u,
IERC20(compounding).balanceOf(address(this))
```

The second attempt to redeem after the AAVE withdraw fails is that the code redeem from Compound.

```solidity
// attempt to redeem compound tokens to the underlying asset
try ICompoundToken(c).redeem(a) {
    // get the balance of underlying assets redeemed
    uint256 balance = IERC20(u).balanceOf(address(this));
    // transfer the underlying back to the user
    Safe.transfer(IERC20(u), msg.sender, balance);
} 
```

However, the return value for ICompoundToken(c).redeem(a) is not handled.

If we looked into the ICompoundToken(c) interface

```solidity
interface ICompoundToken {
    function redeem(uint256) external returns (uint256);
```

Ok it returns (uint256). Why do we have the handle the return value in this case, let us look into the compound token implementation:

https://github.com/compound-finance/compound-protocol/blob/a3214f67b73310d547e00fc578e8355911c9d376/contracts/CErc20.sol#L60

```solidity
  /**
   * @notice Sender redeems cTokens in exchange for the underlying asset
   * @dev Accrues interest whether or not the operation succeeds, unless reverted
   * @param redeemTokens The number of cTokens to redeem into underlying
   * @return uint 0=success, otherwise a failure (see ErrorReporter.sol for details)
   */
  function redeem(uint redeemTokens) override external returns (uint) {
      redeemInternal(redeemTokens);
      return NO_ERROR;
  }
```

Clearly, if return value is 0, meaning sucess, it is fine. Otherwise, the code fail silently unless the error is catched in the Converter code. 

## Impact

The Compound redemption may fail silently and the user gets nothing when redeeming from Pendle, Apwine and Sense.

## Code Snippet

## Tool used

Manual Review

## Recommendation

We recommend the project handle the return value from Compound token redeem. 

If the return value is 0, meaning success, we proceed, otherwise, we log the error message and move to Lido unwrap.