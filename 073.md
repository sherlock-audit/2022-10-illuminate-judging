0x52

medium

# Redeemer#autoRedeem fails to update allowance

## Summary

Redeemer#autoRedeem requires that the user give the redeemer contract allowance but doesn't reduce the balance after the amount is redeemed. This can lead to more than expected shares being redeemed.

## Vulnerability Detail

            uint256 allowance = uToken.allowance(f[i], address(this));
            uint256 amount = pt.balanceOf(f[i]);
            uint256 redeemed = (amount * holdings[u][m]) / pt.totalSupply();
            uint256 fee = redeemed / feenominator;

            if (allowance < amount) {
                revert Exception(20, allowance, amount, address(0), address(0));
            }

            pt.authBurn(f[i], amount);
            holdings[u][m] = holdings[u][m] - redeemed;

            Safe.transfer(uToken, f[i], redeemed - fee);

Redeemer#audoRedeem requires that the user approve the redeemer contract with enough allowance to redeem the shares after maturity. When redeeming, the contract never decreases the allowance.

## Impact

Allowance is not properly updated

## Code Snippet

[Redeemer.sol#L485-L548](https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L485-L548)

## Tool used

Manual Review

## Recommendation

Allowance should be updated to reflect the amount redeemed