rvierdiiev

medium

# Redeemer.setFee function will always revert

## Summary
`Redeemer.setFee` function will always revert and will not give ability to change `feenominator`.
## Vulnerability Detail
`Redeemer.setFee` function is designed to give ability to change `feenominator` variable.

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L168-L187
```solidity
    function setFee(uint256 f) external authorized(admin) returns (bool) {
        uint256 feeTime = feeChange;
        if (feeTime == 0) {
            revert Exception(23, 0, 0, address(0), address(0));
        } else if (feeTime < block.timestamp) {
            revert Exception(
                24,
                block.timestamp,
                feeTime,
                address(0),
                address(0)
            );
        } else if (f < MIN_FEENOMINATOR) {
            revert Exception(25, 0, 0, address(0), address(0));
        }
        feenominator = f;
        delete feeChange;
        emit SetFee(f);
        return true;
    }
```

As `feeChange` value is 0(it's [not set](https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L59) anywhere), this function will always revert wtih `Exception(23, 0, 0, address(0), address(0))`.
Also even if `feeChange` was not 0, the function will give ability to change fee only once, because in the end it calls `delete feeChange` which changes it to 0 again.
## Impact
Fee can't be changed.
## Code Snippet
Provided above.
## Tool used

Manual Review

## Recommendation
Add same functions as in `Lender`.
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L813-L829;