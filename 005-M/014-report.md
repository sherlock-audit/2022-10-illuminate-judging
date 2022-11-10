csanuragjain

medium

# Deposit/mint possible at maturity

## Summary
As per comment on deposit and mint, revert should happen at maturity which wont happen since = check is missing

## Vulnerability Detail
1. Observe the deposit function

```python
/// @notice Before maturity spends `assets` of underlying, and sends `shares` of PTs to `receiver`. Post or at maturity, reverts.

function deposit(address r, uint256 a) external override returns (uint256) {
        if (block.timestamp > maturity) {
            revert Exception(
                21,
                block.timestamp,
                maturity,
                address(0),
                address(0)
            );
        }
...
}
```

2. As per comments the revert should happen Post or at maturity but as per code this only happens post maturity and not at maturity

## Impact
deposit and mint will happen at maturity even though it is not allowed as per comments

## Code Snippet
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/tokens/ERC5095.sol#L149
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/tokens/ERC5095.sol#L176

## Tool used
Manual Review

## Recommendation
Revise the condition as below:

```python
if (block.timestamp >= maturity) {
            revert Exception(
                21,
                block.timestamp,
                maturity,
                address(0),
                address(0)
            );
        }
```