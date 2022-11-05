hansfriese

medium

# `ERC5095.maxWithdraw()` returns the incorrect output.

## Summary
`ERC5095.maxWithdraw()` returns the incorrect output.

## Vulnerability Detail
`ERC5095.maxWithdraw()` should return the maximum amount of underlying token that the `owner` can withdraw.

```solidity
    function maxWithdraw(address o) external view override returns (uint256) {
        if (block.timestamp < maturity) {
            return previewWithdraw(_balanceOf[address(this)]); //@audit M3 address(this)? use preivewRedeem()
        }
        return _balanceOf[o];
    }
```

But it uses `_balanceOf[address(this)]` wrongly instead of `_balanceOf[o]` before maturity.

Also, `previewRedeem()` should be used instead of `previewWithdraw()` because `previewWithdraw()` return the amount of the principal token, not the underlying token.

## Impact
`ERC5095.maxWithdraw()` returns the incorrect result before maturity.

## Code Snippet
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/tokens/ERC5095.sol#L98-L103

## Tool used
Manual Review

## Recommendation
Recommend modifying like below.

```solidity
    function maxWithdraw(address o) external view override returns (uint256) {
        if (block.timestamp < maturity) {
            return previewRedeem(_balanceOf[o]);
        }
        return _balanceOf[o];
    }
```