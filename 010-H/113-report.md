IllIllI

high

# Illuminate redemptions don't account for protocol pauses/temporary blocklistings

## Summary

Illuminate redemptions don't account for protocol pauses/temporary blocklistings

## Vulnerability Detail

By the time that Illuminate PTs have reached maturity, it's assumed that all external PTs will have been converted to underlying, so that the pool of combined underlying from the various protocols can be split on a per-Illuminate-PT-share basis. Unfortunately this may not be the case. Some of the protocol PTs that Illuminate supports as principals allow their own admins [to](https://docs.pendle.finance/docs/information/others/pausing-mechanism) [pause](https://docs.sense.finance/developers/security/#admin) [activity](# https://docs.notional.finance/developer-documentation/on-chain/notional-governance-reference#pauseability), and Illuminate has no way to protect users from redeeming while these protocol pauses are in effect. Unredeemed external PTs contribute zero underlying to the Illuminate PT's underlying balance, and when a user redeemes an Illuminate PT, the PT is burned for its share of what's available, not the total of what could be available in the future.


## Impact

_Permanent freezing of funds_

If a external PT is paused, or its PT is otherwise unable to be redeemed for the full amount when the user requests it, that unredeemed amount of underlying is not claimable (since the user's Illuminate PT is burned), and the user loses that amount of principal. If the external PT is later able to be redeemed, the remaining users will be given the principal that should have gon to the original user.


## Code Snippet

Holdings only increase when external PTs are redeemed successfully:
```solidity
// File: src/Redeemer.sol : Redeemer.redeem()   #1

325            // Calculate how much underlying was redeemed
326            uint256 redeemed = IERC20(u).balanceOf(address(this)) - starting;
327    
328            // Update the holding for this market
329:           holdings[u][m] = holdings[u][m] + redeemed;
```
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L325-L329


```solidity
// File: src/Redeemer.sol : Redeemer.redeem()   #2

385            // Get the amount received
386            uint256 redeemed = IERC20(u).balanceOf(address(this)) - starting;
387    
388            // Verify that underlying are received 1:1 - cannot trust the adapter
389            if (redeemed < amount) {
390                revert Exception(13, 0, 0, address(0), address(0));
391            }
392    
393            // Update the holdings for this market
394:           holdings[u][m] = holdings[u][m] + redeemed;
```
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L385-L394


And user redemptions of Illuminate PTs does not rely on external PT balances, only on the shares of what's available in the currently stored holdings balance at _any_ point after maturity:
```solidity
// File: src/Redeemer.sol : Redeemer.redeem()   #3

413            // Verify the token has matured
414            if (block.timestamp < token.maturity()) {
415                revert Exception(7, block.timestamp, m, address(0), address(0));
416            }
417    
418            // Get the amount of tokens to be redeemed from the sender
419            uint256 amount = token.balanceOf(msg.sender);
420    
421            // Calculate how many tokens the user should receive
422 @>         uint256 redeemed = (amount * holdings[u][m]) / token.totalSupply();
423    
424            // Update holdings of underlying
425            holdings[u][m] = holdings[u][m] - redeemed;
426    
427            // Burn the user's principal tokens
428:           token.authBurn(msg.sender, amount);
```
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L413-L428


```solidity
// File: src/Redeemer.sol : Redeemer.authRedeem()   #4

457            // Make sure the market has matured
458            uint256 maturity = pt.maturity();
459            if (block.timestamp < maturity) {
460                revert Exception(7, maturity, 0, address(0), address(0));
461            }
462    
463            // Calculate the amount redeemed
464 @>         uint256 redeemed = (a * holdings[u][m]) / pt.totalSupply();
465    
466            // Update holdings of underlying
467            holdings[u][m] = holdings[u][m] - redeemed;
468    
469            // Burn the user's principal tokens
470:           pt.authBurn(f, a);
```
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L449-L470


```solidity
// File: src/Redeemer.sol : Redeemer.autoRedeem()   #5

485        function autoRedeem(
486            address u,
487            uint256 m,
488            address[] calldata f
489        ) external returns (uint256) {
490            // Get the principal token for the given market
491            IERC5095 pt = IERC5095(IMarketPlace(marketPlace).token(u, m, 0));
492    
493            // Make sure the market has matured
494            uint256 maturity = pt.maturity();
495            if (block.timestamp < maturity) {
496                revert Exception(7, maturity, 0, address(0), address(0));
497            }
...
514                uint256 amount = pt.balanceOf(f[i]);
515    
516                // Calculate how many tokens the user should receive
517 @>             uint256 redeemed = (amount * holdings[u][m]) / pt.totalSupply();
518    
519                // Calculate the fees to be received (currently .025%)
520                uint256 fee = redeemed / feenominator;
521    
522                // Verify allowance
523                if (allowance < amount) {
524                    revert Exception(20, allowance, amount, address(0), address(0));
525                }
526    
527                // Burn the tokens from the user
528:               pt.authBurn(f[i], amount);
```
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L485-L528


The Illuminate admin has no way to pause/disable redemption for users that try to redeem via `ERC5095.redeem()/withdraw()` or via `autoRedeem()`.

`autoRedeem()` doesn't use the `unpaused` modifier, and does not rely on the normal `redeem()` for redemption:
```solidity
// File: src/Redeemer.sol : Redeemer.u   #6

485        function autoRedeem(
486            address u,
487            uint256 m,
488            address[] calldata f
489 @>     ) external returns (uint256) {
490            // Get the principal token for the given market
491            IERC5095 pt = IERC5095(IMarketPlace(marketPlace).token(u, m, 0));
492    
493            // Make sure the market has matured
494            uint256 maturity = pt.maturity();
495            if (block.timestamp < maturity) {
496:               revert Exception(7, maturity, 0, address(0), address(0));
```
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L485-L496


The ERC5095 also does not use the `unpaused` modifier. It uses `authRedeem()` for its post-maturity redemptions (the pre-maturity redemptions also are not pausable)...:
```solidity
// File: src/tokens/ERC5095.sol : ERC5095.redeem()   #7

284        function redeem(
285            uint256 s,
286            address r,
287            address o
288 @>     ) external override returns (uint256) {
...
318                // Post-maturity
319            } else {
320                if (o == msg.sender) {
321                    return
322 @>                     IRedeemer(redeemer).authRedeem(
323                            underlying,
324                            maturity,
325                            msg.sender,
326                            r,
327                            s
328                        );
329                } else {
330                    uint256 allowance = _allowance[o][msg.sender];
331                    if (allowance < s) {
332                        revert Exception(20, allowance, s, address(0), address(0));
333                    }
334                    _allowance[o][msg.sender] = allowance - s;
335                    return
336 @>                     IRedeemer(redeemer).authRedeem(
337                            underlying,
338                            maturity,
339                            o,
340                            r,
341                            s
342                        );
343                }
344            }
345:       }
```
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/tokens/ERC5095.sol#L284-L345


...and `authRedeem()` does not use the modifier either:

```solidity
// File: src/Redeemer.sol : Redeemer.authRedeem()   #8

443        function authRedeem(
444            address u,
445            uint256 m,
446            address f,
447            address t,
448            uint256 a
449        )
450            external
451 @>         authorized(IMarketPlace(marketPlace).token(u, m, 0))
452            returns (uint256)
453        {
454            // Get the principal token for the given market
455            IERC5095 pt = IERC5095(IMarketPlace(marketPlace).token(u, m, 0));
456    
457            // Make sure the market has matured
458            uint256 maturity = pt.maturity();
459            if (block.timestamp < maturity) {
460                revert Exception(7, maturity, 0, address(0), address(0));
461:           }
```
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L443-L461


## Tool used

Manual Review


## Recommendation

This is hard to solve without missing corner cases, because each external PT may have its own idosyncratic reasons for delays, and there may be losses/slippage involved when redeeming for underlying. I believe the only way that wouldn't allow griefing, would be to track the number of external PTs of each type that were deposited for minting Illuminate PTs on a per-market basis, and `require()` that the number of each that have been redeemed equals the minting count, before allowing the redemption of any Illuminate PTs for that market. You would also need an administrator override that bypasses this check for specific external PTs of specific maturities. All of this assumes that none of the external PTs have rebasing functionality. Also, add the `unpaused` modifier to both `Redeemer.autoRedeem()` and `Redeemer.authRedeem()`.
