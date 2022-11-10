IllIllI

high

# Sense PTs can never be redeemed

## Summary

Sense PTs can never be redeemed


## Vulnerability Detail

Most of the protocols that require the user of the `Converter` contract have code that approves the `Converter` for that protocol, but there is no such approval for Sense.


## Impact

_Permanent freezing of funds_

Users will be able to lend and mint using Sense, but when it's time for Illuminate to redeem the Sense PTs, the call will always revert, meaning the associated underlying will be locked in the contract, and users that try to redeem their Illuminate PTs will have lost principal.

While the Illuminate project does have an emergency `withdraw()` function that would allow an admin to rescue the funds and manually distribute them, this would not be trustless and defeats the purpose of having a smart contract.


## Code Snippet
The Sense flavor of `redeem()` requires the use of the `Converter`:
```solidity
// File: src/Redeemer.sol : Redeemer.redeem()   #1

366            // Get the starting balance to verify the amount received afterwards
367            uint256 starting = IERC20(u).balanceOf(address(this));
368    
369            // Get the divider from the adapter
370            ISenseDivider divider = ISenseDivider(ISenseAdapter(a).divider());
371    
372            // Redeem the tokens from the Sense contract
373            ISenseDivider(divider).redeem(a, s, amount);
374    
375            // Get the compounding token that is redeemed by Sense
376            address compounding = ISenseAdapter(a).target();
377    
378            // Redeem the compounding token back to the underlying
379 @>         IConverter(converter).convert(
380                compounding,
381                u,
382                IERC20(compounding).balanceOf(address(this))
383            );
384    
385            // Get the amount received
386:           uint256 redeemed = IERC20(u).balanceOf(address(this)) - starting;
```
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L366-L386

But there is no code that approves the `Converter` to be able to withdraw from the `Redeemer`. The only function available is required to have been called by the `MarketPlace`, and is thus not callable by the admin:
```solidity
// File: src/Redeemer.sol : Redeemer.approve()   #2

203        function approve(address i) external authorized(marketPlace) {
204            if (i != address(0)) {
205 @>             Safe.approve(IERC20(i), address(converter), type(uint256).max);
206            }
207:       }
```
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L203-L207


Redemptions of Illuminate PTs for underlyings is based on shares of each Illuminate PT's `totalSupply()` of the _available_ underlying, not the expect underlying total:
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L422
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L464
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L517


There is a fork test that tests the converter functionalty, but is uses `vm.startPrank()` to [hack the approval](https://github.com/sherlock-audit/2022-10-illuminate/blob/main/test/fork/Redeemer.t.sol#L370-L372), which wouldn't be available in real life.

Also note that if the admin ever deploys and sets a new converter, that all other redemptions using the converter will break

## Tool used

Manual Review

## Recommendation
Add the sense yield token to the `Redeemer`'s `Converter` approval during market creation/setting of principal
