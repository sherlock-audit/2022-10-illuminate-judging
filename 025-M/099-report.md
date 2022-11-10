IllIllI

medium

# There can only ever be one market with USDT as the underlying

## Summary

There can only ever be one market with USDT as the underlying


## Vulnerability Detail

USDT, and other tokens that have [approval race protections](https://github.com/d-xo/weird-erc20#approval-race-protections) will revert when `approve()` is called if the current approval isn't currently zero. The `MarketPlace` contract always approves the underlying during market creation, and on the second market created, the creation will revert.


## Impact

_Smart contract unable to operate due to lack of token funds_

No USDT markets except for the first one will be able to be created. An admin can work around this by passing `0x0` as every entry in the principal array, and later calling `setPrincipal()`, but this is error-prone, especially since once set, principals are immutable. 


## Code Snippet
`Marketplace.createMarket()` unconditionally calls `Lender.approve()`:
```solidity
// File: src/MarketPlace.sol : MarketPlace.createMarket()   #1

178                // Set the market
179                markets[u][m] = market;
180    
181                // Have the lender contract approve the several contracts
182: @>            ILender(lender).approve(u, e, a, t[7]);
```
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Marketplace.sol#L178-L182


`approve()` is called on the underlying if the `e`, `a`, or `t[7]` arguments are non-null:
```solidity
// File: src/Lender.sol : Lender.approve()   #2

194        function approve(
195            address u,
196            address a,
197            address e,
198            address n
199        ) external authorized(marketPlace) {
200            uint256 max = type(uint256).max;
201            IERC20 uToken = IERC20(u);
202            if (a != address(0)) {
203                Safe.approve(uToken, a, max);
204            }
205            if (e != address(0)) {
206                Safe.approve(uToken, e, max);
207            }
208            if (n != address(0)) {
209                Safe.approve(uToken, n, max);
210            }
211            if (IERC20(u).allowance(address(this), swivelAddr) == 0) {
212                Safe.approve(uToken, swivelAddr, max);
213            }
214:       }
```
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L194-L214

If CTokens ever are upgraded to have the protection, a similar approval issue will occur for the PTs themselves.

## Tool used

Manual Review


## Recommendation

Modify `Safe.approve()` to always call `approve(0)` before doing the real approval


