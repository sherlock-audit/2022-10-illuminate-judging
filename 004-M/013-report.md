csanuragjain

medium

# User can steal contract existing balance

## Summary
If contract has an existing balance while converting then user can sweep away that existing balance as part of conversion

## Vulnerability Detail
1. Assume contract has existing balance of amount 100
2. User A calls the convert function which went for Lido conversion using amount 50

```python
function convert(
        address c,
        address u,
        uint256 a
    ) external {
...
catch {
                // get the current balance of wstETH
                uint256 balance = IERC20(c).balanceOf(address(this));
                // unwrap wrapped staked eth
                uint256 unwrapped = ILido(c).unwrap(balance);
                // Send the unwrapped staked ETH to the caller
                Safe.transfer(IERC20(u), msg.sender, unwrapped);
            }
}
```

3. In this case balance will be come as 150 even though user only paid amount 50 due to previous balance causing conversion in giving more amount to user than required

## Impact
User will more underlying token even though he paid lesser compounding token

## Code Snippet
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Converter.sol#L21

## Tool used
Manual Review

## Recommendation
Revise the function as below:

```python
function convert(
        address c,
        address u,
        uint256 a
    ) external {
uint256 prevBalance = IERC20(c).balanceOf(address(this));
Safe.transferFrom(IERC20(c), msg.sender, address(this), a);
...
catch {
                // get the current balance of wstETH
                uint256 balance = IERC20(c).balanceOf(address(this));
balance-=prevBalance;
                // unwrap wrapped staked eth
                uint256 unwrapped = ILido(c).unwrap(balance);
                // Send the unwrapped staked ETH to the caller
                Safe.transfer(IERC20(u), msg.sender, unwrapped);
            }
```