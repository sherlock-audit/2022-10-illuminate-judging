IllIllI

high

# Fee-on-transfer underlyings can be used to mint Illuminate PTs without fees

## Summary

Fee-on-transfer underlyings can be used to mint Illuminate PTs without fees


## Vulnerability Detail

Illuminate's `Lender` does not confirm that the amount of underlying received is the amount provided in the transfer call. If the token is a fee-on-transfer token (e.g. USDT which is [currently](https://github.com/sherlock-audit/2022-10-illuminate/blob/main/test/fork/Contracts.sol#L98) [supported](https://github.com/sherlock-audit/2022-10-illuminate/blob/main/test/fork/Contracts.sol#L61-L62)), then the amount may be less. As long as the fee is smaller than Illuminate's fee, Illuminate will incorrectly trust that the fee has properly been deducted from the contract's balance, and then will swap the funds and mint an Illuminate PT.


## Impact

_Theft of unclaimed yield_

Attackers can mint free PT at the expense of Illuminate's fees.


## Code Snippet

This is one example from one of the `lend()` functions, but they all have the same issue:

```solidity
// File: src/Lender.sol : Lender.lend()   #1

750        function lend(
751            uint8 p,
752            address u,
753            uint256 m,
754            uint256 a,
755            uint256 r
756        ) external unpaused(u, m, p) returns (uint256) {
757            // Instantiate Notional princpal token
758            address token = IMarketPlace(marketPlace).token(u, m, p);
759    
760            // Transfer funds from user to Illuminate
761  @>        Safe.transferFrom(IERC20(u), msg.sender, address(this), a);
762    
763            // Add the accumulated fees to the total
764            uint256 fee = a / feenominator;
765            fees[u] = fees[u] + fee;
766    
767            // Swap on the Notional Token wrapper
768  @>        uint256 received = INotional(token).deposit(a - fee, address(this));
769    
770            // Verify that we received the principal tokens
771            if (received < r) {
772                revert Exception(16, received, r, address(0), address(0));
773            }
774    
775            // Mint Illuminate zero coupons
776  @>        IERC5095(principalToken(u, m)).authMint(msg.sender, received);
777    
778            emit Lend(p, u, m, received, a, msg.sender);
779            return received;
780:       }
```
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L750-L780


And separately, if any of the external PTs ever become fee-on-transfer (e.g. CTokens, which are upgradeable), users would be able to mint Illuminate PT directly without having to worry about the FOT fee being smaller than the illuminate one, and the difference would be made up by other PT holders' principal, rather than Illuminate's fees:

```solidity
// File: src/Lender.sol : Lender.mint()   #2

270        function mint(
271            uint8 p,
272            address u,
273            uint256 m,
274            uint256 a
275        ) external unpaused(u, m, p) returns (bool) {
276            // Fetch the desired principal token
277            address principal = IMarketPlace(marketPlace).token(u, m, p);
278    
279            // Transfer the users principal tokens to the lender contract
280 @>         Safe.transferFrom(IERC20(principal), msg.sender, address(this), a);
281    
282            // Mint the tokens received from the user
283 @>         IERC5095(principalToken(u, m)).authMint(msg.sender, a);
284    
285            emit Mint(p, u, m, a);
286    
287            return true;
288:       }
```
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L270-L288


## POC

Imagine that the Illuminate fee is 1%, and the fee-on-transfer fee for USDT is also 1%
1. A random unaware user calls one of the `lend()` functions for 100 USDT
2. `lend()` does the `transferFrom()` for the user and gets 99 USDT due to the USDT 1% fee
3. `lend()` calculates its own fee as 1% of 100, resulting in 99 USDT remaining
4. `lend()` swaps the 99 USDT for a external PT
5. the user is given 99 IPT and only had to spend 100 USDT, and Illuminate got zero actual fee, and actually has to make up the difference itself in order to withdraw _any_ fees (see other issue I've filed about this).


## Tool used

Manual Review


## Recommendation

Check the actual balance before and after the transfer, and ensure the amount is correct, or use the difference as the amount

