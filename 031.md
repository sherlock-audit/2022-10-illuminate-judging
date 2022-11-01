rvierdiiev

high

# ERC5095.mint function calculates slippage incorrectly

## Summary
ERC5095.mint function calculates slippage incorrectly. This leads to lost of funds for user.
## Vulnerability Detail
`ERC5095.mint` function should take amount of shares that user wants to receive and then buy this amount. It uses hardcoded 1% slippage when trades base tokens for principal. But it takes 1% of calculated assets amount, not shares.

```solidity
    function mint(address r, uint256 s) external override returns (uint256) {
        if (block.timestamp > maturity) {
            revert Exception(
                21,
                block.timestamp,
                maturity,
                address(0),
                address(0)
            );
        }
        uint128 assets = Cast.u128(previewMint(s));
        Safe.transferFrom(
            IERC20(underlying),
            msg.sender,
            address(this),
            assets
        );
        // consider the hardcoded slippage limit, 4626 compliance requires no minimum param.
        uint128 returned = IMarketPlace(marketplace).sellUnderlying(
            underlying,
            maturity,
            assets,
            assets - (assets / 100)
        );
        _transfer(address(this), r, returned);
        return returned;
    }
```

This is how slippage is provided
```solidity
uint128 returned = IMarketPlace(marketplace).sellUnderlying(
            underlying,
            maturity,
            assets,
            assets - (assets / 100)
        );
```

But the problem is that assets it is amount of base tokens that user should pay for the shares he want to receive. Slippage should be calculated using shares amount user expect to get.

Example.
User calls mint and provides amount 1000. That means that he wants to get 1000 principal tokens. While converting to assets, assets = 990. That means that user should pay 990 base tokens to get 1000 principal tokens.
Then the `sellUnderlying` is send and slippage provided is `990*0.99=980.1`. So when something happens with price it's possible that user will receive 980.1 principal tokens instead of 1000 which is 2% lost. 

To fix this you should provide `s - (s / 100)` as slippage.
## Impact
Lost of users funds.
## Code Snippet
Provided above
## Tool used

Manual Review

## Recommendation
Use this.
```solidity
uint128 returned = IMarketPlace(marketplace).sellUnderlying(
            underlying,
            maturity,
            assets,
            s- (s / 100)
        );
```