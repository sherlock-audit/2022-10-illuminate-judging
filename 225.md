HonorLt

medium

# Wrong default slippage

## Summary
When withdrawing and selling the principal token it incorrectly calculates the default slippage.

## Vulnerability Detail
When withdrawing in ERC5095 it sells ```shares``` but calculates slippage on ```a``` underlying:
```solidity
  uint128 shares = Cast.u128(previewWithdraw(a));
  // If owner is the sender, sell PT without allowance check
  if (o == msg.sender) {
      uint128 returned = IMarketPlace(marketplace).sellPrincipalToken(
          underlying,
          maturity,
          shares,
          Cast.u128(a - (a / 100))
      );
```

One more issue regarding slippage:
function yield reverts when ```received = m```:
```solidity
        // Verify receipt of PTs from Yield Space Pool
        if (received <= m) {
            revert Exception(11, received, m, address(0), address(0));
        }
```
It should be okay if you received the exact minimum amount, so the condition has to be ```<``` here.

## Impact
This may lead to unpredicted slippage control when the amount of underlying and shares differs much.

## Code Snippet

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/tokens/ERC5095.sol#L216-L224

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L951-L954

## Tool used

Manual Review

## Recommendation
Based on my understanding, the slippage should be:
```solidity
  shares  - (shares / 100)
```
