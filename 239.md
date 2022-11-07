hyh

medium

# autoRedeem might be run before all external PT were redeemed

## Summary

Redeemer's autoRedeem() will issue the fee to the **first** caller, creating the incentives to run it sooner than later, even before all versions of external PTs redeem will be successfully run.

## Vulnerability Detail

Interests of the Illuminate PT holders and third-party running the autoRedeem might differ as this third party might want to run it fast, while the owners do want to run it only after all external PT types were redeemed.

I.e. a runner can avoid waiting for the all redeems to be completed, while it is against the interests of the owners.

## Impact

Illuminate PT holders can obtain less funds, i.e. not optimal amount of the funds, skipping some types of PTs.

This is permanent loss for them as autoRedeem() result cannot be altered after it was run.

## Code Snippet

autoRedeem() can be run by anyone and prematurely:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L479-L489

```solidity
    /// @notice implements a redeem method to enable third-party redemptions
    /// @dev expects approvals from owners to redeemer
    /// @param u address of the underlying asset
    /// @param m maturity of the market
    /// @param f address from where the principal token will be burned
    /// @return uint256 amount of underlying yielded as a fee
    function autoRedeem(
        address u,
        uint256 m,
        address[] calldata f
    ) external returns (uint256) {
```

## Tool used

Manual Review

## Recommendation

Consider adding the check for Lender balance to ensure that there are no external PTs left there.

Prohibit autoRedeem before that. The costs of this check are well compensated by the fee third-party receives.