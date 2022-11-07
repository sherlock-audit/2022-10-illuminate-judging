hyh

high

# Sense redeem is unavailable and funds are frozen for underlyings whose decimals are smaller than the corresponding IBT decimals

## Summary

Sense version of Redeemer's redeem() compares `amount` of Sense principal token Lender had on its balance vs `redeemed` amount of underlying as a slippage check, requiring that the latter be equal or greater than the former.

As these numbers have different decimals this check blocks the redeem altogether for the tokens whose decimals are smaller than decimals of the corresponding interest bearing token, freezing the funds.

## Vulnerability Detail

Sense version of redeem() assumes that Sense PT has the same decimals as underlying, performing slippage check by directly comparing the amounts.

Sense principal has decimals of the corresponding interest bearing tokens, not the decimals of the underlying. In the compound case IBT decimals are `8` and can be greater or less than underlying's.

For example, `1st July 2023 cUSDC Sense Principal Token` has `8` decimals, as cUSDC does (instead of 6 as USDC):

https://etherscan.io/token/0x869a70c198c937801b26d2701dc8e4e8c4de354a

In this case the slippage check reverts the operation. Sense PT cannot be turned to underlying and will remain on Lender's balance this way.

On the other hand, when underlying decimals are greater than IBT decimals the slippage check becomes a noop.

## Impact

Protocol users can be subject to market manipulations as Sense AMM result isn't checked for the underlyings whose decimals are higher than decimals of the corresponding IBT, say in the cDAI (8) and DAI (18) case. I.e. sandwich attacks have high possibility in this case whenever amounts are big enough.

Sense redeem will be unavailable and funds frozen for the underlyings whose decimals are smaller than decimals of the corresponding IBT, say in the cUSDC (8) and USDC (6) case. 

As without working redeem() the whole Sense PT funds be frozen for all the users as it deals with the cumulative holdings of the protocol, setting the severity to be high.

## Code Snippet

Sense redeem() compares `amount` of Sense PT to `redeemed` amount of underlying in order to `Verify that underlying are received 1:1`:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L335-L394

```solidity
    /// @notice redeem method signature for Sense
    /// @param p principal value according to the MarketPlace's Principals Enum
    /// @param u address of an underlying asset
    /// @param m maturity (timestamp) of the market
    /// @param s Sense's maturity is needed to extract the pt address
    /// @param a Sense's adapter for this market
    /// @return bool true if the redemption was successful
    function redeem(
        uint8 p,
        address u,
        uint256 m,
        uint256 s,
        address a
    ) external returns (bool) {
        // Check the principal is Sense
        if (p != uint8(MarketPlace.Principals.Sense)) {
            revert Exception(6, p, 0, address(0), address(0));
        }

        // Get Sense's principal token for this market
        IERC20 token = IERC20(IMarketPlace(marketPlace).token(u, m, p));

        // Cache the lender to save on SLOAD operations
        address cachedLender = lender;

        // Get the balance of tokens to be redeemed by the user
        uint256 amount = token.balanceOf(cachedLender);

        // Transfer the user's tokens to the redeem contract
        Safe.transferFrom(token, cachedLender, address(this), amount);

        // Get the starting balance to verify the amount received afterwards
        uint256 starting = IERC20(u).balanceOf(address(this));

        ...

        // Redeem the compounding token back to the underlying
        IConverter(converter).convert(
            compounding,
            u,
            IERC20(compounding).balanceOf(address(this))
        );

        // Get the amount received
        uint256 redeemed = IERC20(u).balanceOf(address(this)) - starting;

        // Verify that underlying are received 1:1 - cannot trust the adapter
        if (redeemed < amount) {
            revert Exception(13, 0, 0, address(0), address(0));
        }

        // Update the holdings for this market
        holdings[u][m] = holdings[u][m] + redeemed;
```

This way, for example, 8 decimals amount of `1st July 2023 cUSDC Sense Principal Token`, say `1e3*1e8` for `1000 PT`, is checked to be greater than `1e3*1e6` for `1000 USDC`, which basically is never true. Same holds for any Sense USDC PT.

On the other hand, for example DAI, having 18 decimals, will always pass this check as Sense cDAI PT has cDAI decimals of 8, for example (from https://docs.sense.finance/developers/deployed-contracts/):

https://etherscan.io/token/0xcfA7B126c680007D0367d0286D995c6aEE53e087

## Tool used

Manual Review

## Recommendation

In order to verify `redeemed = IERC20(u).balanceOf(address(this)) - starting` vs initial `IERC20(IMarketPlace(marketPlace).token(u, m, p))`'s balance of Lender, consider introducing the decimals adjustment multiplier, i.e. read Sense PT decimals, underlying decimals, and multiply the smaller decimals amount to match the bigger decimals one in order to compare.