rvierdiiev

medium

# Marketplace.setPrincipal do not approve needed allowance for Element vault and APWine router

## Summary
`Marketplace.setPrincipal` do not approve needed allowance for `Element vault` and `APWine router`
## Vulnerability Detail
`Marketplace.setPrincipal` is used to provide principal token for the base token and maturity when it was not set yet. To set PT you also provide protocol that this token belongs to.

In case of `APWine` protocol there is special block of code to handle all needed allowance. But it is not enough.

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Marketplace.sol#L231-L236
```solidity
        } else if (p == uint8(Principals.Apwine)) {
            address futureVault = IAPWineToken(a).futureVault();
            address interestBearingToken = IAPWineFutureVault(futureVault)
                .getIBTAddress();
            IRedeemer(redeemer).approve(interestBearingToken);
        } else if (p == uint8(Principals.Notional)) {
```

In `Marketplace.createMarket` function 2 more params are used to provide allowance of Lender for Element vault and APWine router.
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Marketplace.sol#L182
`ILender(lender).approve(u, e, a, t[7]);`

But in `setPrincipal` we don't have such params and allowance is not set. So `Lender` will not be able to work with that tokens correctly.
## Impact
Lender will not provide needed allowance and protocol integration will fail.
## Code Snippet
Provided above.
## Tool used

Manual Review

## Recommendation
Add 2 more params as in `createMarket` and call `ILender(lender).approve(u, e, a, address(0));`