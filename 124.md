hansfriese

high

# `ERC5095.withdraw()` and `ERC5095.redeem()` don't transfer the principal token to the contract when they work before maturity.

## Summary
`ERC5095.withdraw()` and `ERC5095.redeem()` don't transfer the principal token to the contract when they work before maturity.

## Vulnerability Detail
`ERC5095.withdraw()` and `ERC5095.redeem()` are used to withdraw/redeem the principal token and receive the underlying token.

These functions are available before maturity as well and they exchange from the principal token to the underlying using the marketplace in this case.

But they don't transfer the principal token to the contract properly and let me explain in detail with [withdraw()](https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/tokens/ERC5095.sol#L215-L249) function.

```solidity
    if (block.timestamp < maturity) {
        uint128 shares = Cast.u128(previewWithdraw(a));
        // If owner is the sender, sell PT without allowance check
        if (o == msg.sender) {
            uint128 returned = IMarketPlace(marketplace).sellPrincipalToken(
                underlying,
                maturity,
                shares,
                Cast.u128(a - (a / 100))
            );
            Safe.transfer(IERC20(underlying), r, returned);
            return returned;
            // Else, sell PT with allowance check
        } else {
            uint256 allowance = _allowance[o][msg.sender];
            if (allowance < shares) {
                revert Exception(
                    20,
                    allowance,
                    shares,
                    address(0),
                    address(0)
                );
            }
            _allowance[o][msg.sender] = allowance - shares;
            uint128 returned = IMarketPlace(marketplace).sellPrincipalToken(
                underlying,
                maturity,
                Cast.u128(shares),
                Cast.u128(a - (a / 100))
            );
            Safe.transfer(IERC20(underlying), r, returned);
            return returned;
        }
    }
```

In the `withdraw()` function, it calls `MarketPlace.sellPrincipalToken()` to exchange from the pricipal to underlying [here](https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/tokens/ERC5095.sol#L219) and [here](https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/tokens/ERC5095.sol#L240).

And [MarketPlace.sellPrincipalToken()](https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Marketplace.sol#L285) exchanges using the pool.

```solidity
    function sellPrincipalToken(
        address u,
        uint256 m,
        uint128 a,
        uint128 s
    ) external returns (uint128) {
        // Get the pool for the market
        IPool pool = IPool(pools[u][m]);

        // Preview amount of underlying received by selling `a` PTs
        uint256 expected = pool.sellFYTokenPreview(a);

        if (expected < s) {
            revert Exception(16, expected, s, address(0), address(0));
        }

        // Transfer the principal tokens to the pool
        Safe.transferFrom(
            IERC20(address(pool.fyToken())),
            msg.sender,
            address(pool),
            a
        );

        // Execute the swap
        uint128 received = pool.sellFYToken(msg.sender, uint128(expected));
        emit Swap(u, m, address(pool.fyToken()), u, received, a, msg.sender);

        return received;
    }
```

It transfers the principal token to the pool [here](https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Marketplace.sol#L301-L307) from `msg.sender`.

So when this function is called from the `ERC5095` contract, `msg.sender` will be the `ERC5095` contract itself.

But in the `ERC5095.withdraw()`, it doesn't transfer the principal token from `msg.sender` to the contract so that the balance of the contract itself will be used.

After all, if the contract has some balance already, a malicious caller can receive the underlying token for free and if the contract doesn't have any balance, `withdraw()` will always revert.

## Impact
`ERC5095.withdraw()` and `ERC5095.redeem()` will always revert when the `ERC5095` contract doesn't have enough balance of the principal token.

If not, the users can earn the underlying token for free by burning the contract's balance.

## Code Snippet
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/tokens/ERC5095.sol#L218-L248
https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/tokens/ERC5095.sol#L293-L317

## Tool used
Manual Review

## Recommendation
We should transfer the principal token to the contract before calling the `sellPrincipalToken()` function in `ERC5095.withdraw()` and `ERC5095.redeem()`.

```solidity
    function withdraw( //@audit don't transfer principal token to this contract from msg.sender
        uint256 a,
        address r,
        address o
    ) external override returns (uint256) {
        // Pre maturity
        if (block.timestamp < maturity) {
            uint128 shares = Cast.u128(previewWithdraw(a));
            // If owner is the sender, sell PT without allowance check
            if (o == msg.sender) {
                _transfer(msg.sender, address(this), shares); //++++++++++++++++++++++++++++++++
                uint128 returned = IMarketPlace(marketplace).sellPrincipalToken(
                    underlying,
                    maturity,
                    shares,
                    Cast.u128(a - (a / 100))
                );
                Safe.transfer(IERC20(underlying), r, returned);
                return returned;
                // Else, sell PT with allowance check
            } else {
                uint256 allowance = _allowance[o][msg.sender];
                if (allowance < shares) {
                    revert Exception(
                        20,
                        allowance,
                        shares,
                        address(0),
                        address(0)
                    );
                }
                _allowance[o][msg.sender] = allowance - shares;
                _transfer(o, address(this), shares); //++++++++++++++++++++++++++++++++
                uint128 returned = IMarketPlace(marketplace).sellPrincipalToken(
                    underlying,
                    maturity,
                    Cast.u128(shares),
                    Cast.u128(a - (a / 100))
                );
                Safe.transfer(IERC20(underlying), r, returned);
                return returned;
            }
        }
```