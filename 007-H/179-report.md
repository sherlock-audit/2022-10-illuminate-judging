hyh

high

# Yield, Swivel, Element, APWine and Sense lend() are subject to reentracy resulting in Illuminate PT over-mint

## Summary

Lender's lend() versions for Yield, Swivel, Element, APWine and Sense use balance difference for the net result calculation, i.e. how much Illuminate PTs to mint for the caller, and call user-provided contract to perform the swapping. The functions aren't protected from reentrancy.

This opens up an attack surface when the functions are being called repetitively, and, while the first call result is accounted once, nested calls, dealing with the same type of PTs, are accounted multiple times, leading to severe Illuminate PT over-mint.

## Vulnerability Detail

Taking Yield version as an example, Bob the attacker can provide custom-made contract `y` instead of Yield Space Pool. `y` do call the real pool, but before that it calls the same lend() with the same parameters (apart from amount), so `y` got called again.

Let's say it happens 2 extra times. Let's say the first call is done with `10 DAI`, the second with `100 DAI`, the third with `10^6 DAI`, i.e. Bob needs to provide `10^6 + 10^2 + 10^1 DAI`. Let's say it is done right before maturity and there is no discounting remaining, i.e. `1 DAI = 1 PT`.

The result of the first yield() call will be accounted once, as designed. The result of the second, nested, call, will be accounted twice as it mints to the user according to the yield() call performed and increases the Yield PT balance, which is counted in the first lend(). The result of the third call will be accounted in all lend() functions.

This way first lend() will mint `1 * 10^6 + 1 * 10^2 + 1 * 10^1` as it will be the total Yield PT balance difference from the three yield() calls it performed directly and nested, i.e. the balance will be counted before the swapping started, the second time it will be counted when all three swaps be completed. The second lend() will mint `1 * 10^6 + 1 * 10^2` as it be finished before first yield() do its swap. The third lend() will mint `1 * 10^6`, having no further calls nested.

Bob will get `3 * 10^6 + 2 * 10^2 + 1 * 10^1` Illuminate PT minted for the `10^6 + 10^2 + 10^1` DAI provided.

## Impact

The impact is massive Illuminate PTs over-mint that result in attacker being able to steal the funds of all other users by redeeming first the whole underlying amount due to the type of Illuminate PTs he obtained.

As there are no low probability prerequisites, setting the severity to be high.

## Code Snippet

Similar in all: Bob creates a wrapper that calls the same version of lend() with the same parameters, then calls the correct pool. In each version of lend() there are a user-provided contract that is called to perform the operation, allowing for reentracy.

Yield lend() calls yield() with user-provided contract `y`, that is called in-between balance recording:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L290-L347

```solidity
    /// @notice lend method for the Illuminate and Yield protocols
    /// @param p principal value according to the MarketPlace's Principals Enum
    /// @param u address of an underlying asset
    /// @param m maturity (timestamp) of the market
    /// @param a amount of underlying tokens to lend
    /// @param y Yield Space Pool for the principal token
    /// @param minimum slippage limit, minimum amount to PTs to buy
    /// @return uint256 the amount of principal tokens lent out
    function lend(
        uint8 p,
        address u,
        uint256 m,
        uint256 a,
        address y,
        uint256 minimum
    ) external unpaused(u, m, p) returns (uint256) {
        // Check that the principal is Illuminate or Yield
        if (
            p != uint8(MarketPlace.Principals.Illuminate) &&
            p != uint8(MarketPlace.Principals.Yield)
        ) {
            revert Exception(6, 0, 0, address(0), address(0));
        }

        // Get principal token for this market
        address principal = IMarketPlace(marketPlace).token(u, m, p);

        // Extract fee
        fees[u] = fees[u] + a / feenominator;

        // Transfer underlying from user to the lender contract
        Safe.transferFrom(IERC20(u), msg.sender, address(this), a);

        if (p == uint8(MarketPlace.Principals.Yield)) {
            // Make sure the Yield Space Pool matches principal token
            address fyToken = IYield(y).fyToken();
            if (IYield(y).fyToken() != principal) {
                revert Exception(12, 0, 0, fyToken, principal);
            }
        }

        // Swap underlying for PTs to lender
        uint256 returned = yield(
            u,
            y,
            a - a / feenominator,
            address(this),
            principal,
            minimum
        );

        // Mint Illuminate PTs to msg.sender
        IERC5095(principalToken(u, m)).authMint(msg.sender, returned);

        emit Lend(p, u, m, returned, a, msg.sender);

        return returned;
    }
```

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L919-L957

```solidity
    /// @notice swaps underlying premium via a Yield Space Pool
    /// @dev this method is only used by the Yield, Illuminate and Swivel protocols
    /// @param u address of an underlying asset
    /// @param y Yield Space Pool for the principal token
    /// @param a amount of underlying tokens to lend
    /// @param r the receiving address for PTs
    /// @param p the principal token in the Yield Space Pool
    /// @param m the minimum amount to purchase
    /// @return uint256 the amount of tokens sent to the Yield Space Pool
    function yield(
        address u,
        address y,
        uint256 a,
        address r,
        address p,
        uint256 m
    ) internal returns (uint256) {
        // Get the starting balance (to verify receipt of tokens)
        uint256 starting = IERC20(p).balanceOf(r);

        // Get the amount of tokens received for swapping underlying
        uint128 returned = IYield(y).sellBasePreview(Cast.u128(a));

        // Send the remaining amount to the Yield pool
        Safe.transfer(IERC20(u), y, a);

        // Lend out the remaining tokens in the Yield pool
        IYield(y).sellBase(r, returned);

        // Get the ending balance of principal tokens (must be at least starting + returned)
        uint256 received = IERC20(p).balanceOf(r) - starting;

        // Verify receipt of PTs from Yield Space Pool
        if (received <= m) {
            revert Exception(11, received, m, address(0), address(0));
        }

        return received;
    }
```

Similarly, Swivel lend() calls yield() with user-supplied Yield Space Pool `y` via swivelLendPremium():

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L349-L449

```solidity
    /// @notice lend method signature for Swivel
    /// @param p principal value according to the MarketPlace's Principals Enum
    /// @param u address of an underlying asset
    /// @param m maturity (timestamp) of the market
    /// @param a array of amounts of underlying tokens lent to each order in the orders array
    /// @param y Yield Space Pool for the Illuminate PT in this market
    /// @param o array of Swivel orders being filled
    /// @param s array of signatures for each order in the orders array
    /// @param e flag to indicate if returned funds should be swapped in Yield Space Pool
    /// @param premiumSlippage slippage limit, minimum amount to PTs to buy
    /// @return uint256 the amount of principal tokens lent out
    function lend(
        uint8 p,
        address u,
        uint256 m,
        uint256[] memory a,
        address y,
        Swivel.Order[] calldata o,
        Swivel.Components[] calldata s,
        bool e,
        uint256 premiumSlippage
    ) external unpaused(u, m, p) returns (uint256) {
        {
            // Check that the principal is Swivel
            if (p != uint8(MarketPlace.Principals.Swivel)) {
 				...
            }

            // Lent represents the total amount of underlying to be lent
            uint256 lent = swivelAmount(a);

            // Transfer underlying token from user to Illuminate
            Safe.transferFrom(IERC20(u), msg.sender, address(this), lent);

            // Get the underlying balance prior to calling initiate
            uint256 starting = IERC20(u).balanceOf(address(this));

            // Verify and collect the fee
            {
            	...
            }

            uint256 received;
            {
                // Get the starting amount of principal tokens
                uint256 startingZcTokens = IERC20(
                    IMarketPlace(marketPlace).token(u, m, p)
                ).balanceOf(address(this));

                // Fill the given orders on Swivel
                ISwivel(swivelAddr).initiate(o, a, s);

                if (e) {
                    // Calculate the premium
                    uint256 premium = IERC20(u).balanceOf(address(this)) -
                        starting;

                    // Swap the premium for Illuminate principal tokens
                    swivelLendPremium(u, m, y, premium, premiumSlippage);
                }

                // Compute how many principal tokens were received
                received =
                    IERC20(IMarketPlace(marketPlace).token(u, m, p)).balanceOf(
                        address(this)
                    ) -
                    startingZcTokens;
            }

            // Mint Illuminate principal tokens to the user
            IERC5095(principalToken(u, m)).authMint(msg.sender, received);

            {
                emit Lend(
                	...
                );
            }
            return received;
        }
    }
```

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L959-L979

```solidity
    /// @notice lends the leftover underlying premium to the Illuminate PT's Yield Space Pool
    function swivelLendPremium(
        address u,
        uint256 m,
        address y,
        uint256 p,
        uint256 slippageTolerance
    ) internal {
        // Lend remaining funds to Illuminate's Yield Space Pool
        uint256 swapped = yield(
            u,
            y,
            p,
            address(this),
            IMarketPlace(marketPlace).token(u, m, 0),
            slippageTolerance
        );

        // Mint the remaining tokens
        IERC5095(principalToken(u, m)).authMint(msg.sender, swapped);
    }
```

This way both Yield and Swivel call yield() with user-supplied pool `y` and mint the difference obtained with the `y` call to a user.

Element lend calls elementSwap() with user-supplied pool `e` and mints the balance difference:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L451-L511

```solidity
    /// @notice lend method signature for Element
    /// @param p principal value according to the MarketPlace's Principals Enum
    /// @param u address of an underlying asset
    /// @param m maturity (timestamp) of the market
    /// @param a amount of underlying tokens to lend
    /// @param r slippage limit, minimum amount to PTs to buy
    /// @param d deadline is a timestamp by which the swap must be executed
    /// @param e Element pool that is lent to
    /// @param i the id of the pool
    /// @return uint256 the amount of principal tokens lent out
    function lend(
        uint8 p,
        address u,
        uint256 m,
        uint256 a,
        uint256 r,
        uint256 d,
        address e,
        bytes32 i
    ) external unpaused(u, m, p) returns (uint256) {
        // Get the principal token for this market for Element
        address principal = IMarketPlace(marketPlace).token(u, m, p);

        // Transfer underlying token from user to Illuminate
        Safe.transferFrom(IERC20(u), msg.sender, address(this), a);

        // Track the accumulated fees
        fees[u] = fees[u] + a / feenominator;

        uint256 purchased;
        {
        	...

            // Conduct the swap on Element
            purchased = elementSwap(e, swap, fund, r, d);
        }

        // Mint tokens to the user
        IERC5095(principalToken(u, m)).authMint(msg.sender, purchased);

        emit Lend(p, u, m, purchased, a, msg.sender);
        return purchased;
    }
```

elementSwap() similarly calls user-supplied `e` to perform the swapping and mints the balance difference:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L1000-L1028

```solidity
    /// @notice executes a swap for and verifies receipt of Element PTs
    function elementSwap(
        address e,
        Element.SingleSwap memory s,
        Element.FundManagement memory f,
        uint256 r,
        uint256 d
    ) internal returns (uint256) {
        // Get the principal token
        address principal = address(s.assetOut);

        // Get the intial balance
        uint256 starting = IERC20(principal).balanceOf(address(this));

        // Conduct the swap on Element
        IElementVault(e).swap(s, f, r, d);

        // Get how many PTs were purchased by the swap call
        uint256 purchased = IERC20(principal).balanceOf(address(this)) -
            starting;

        // Verify that a minimum amount was received
        if (purchased < r) {
            revert Exception(11, 0, 0, address(0), address(0));
        }

        // Return the net amount of principal tokens acquired after the swap
        return purchased;
    }
```

APWine lend() in the same manner calls user-supplied pool `x` and mints the balance difference `received`:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L562-L621

```solidity
    /// @notice lend method signature for APWine
    /// @param p principal value according to the MarketPlace's Principals Enum
    /// @param u address of an underlying asset
    /// @param m maturity (timestamp) of the market
    /// @param a amount of underlying tokens to lend
    /// @param r slippage limit, minimum amount to PTs to buy
    /// @param d deadline is a timestamp by which the swap must be executed
    /// @param x APWine router that executes the swap
    /// @param pool the AMM pool used by APWine to execute the swap
    /// @return uint256 the amount of principal tokens lent out
    function lend(
        uint8 p,
        address u,
        uint256 m,
        uint256 a,
        uint256 r,
        uint256 d,
        address x,
        address pool
    ) external unpaused(u, m, p) returns (uint256) {
        address principal = IMarketPlace(marketPlace).token(u, m, p);

        // Transfer funds from user to Illuminate
        Safe.transferFrom(IERC20(u), msg.sender, address(this), a);

        uint256 lent;
        {
            // Add the accumulated fees to the total
            uint256 fee = a / feenominator;
            fees[u] = fees[u] + fee;

            // Calculate amount to be lent out
            lent = a - fee;
        }

        // Get the starting APWine token balance
        uint256 starting = IERC20(principal).balanceOf(address(this));

        // Swap on the APWine Pool using the provided market and params
        IAPWineRouter(x).swapExactAmountIn(
            pool,
            apwinePairPath(),
            apwineTokenPath(),
            lent,
            r,
            address(this),
            d,
            address(0)
        );

        // Calculate the amount of APWine principal tokens received after the swap
        uint256 received = IERC20(principal).balanceOf(address(this)) -
            starting;

        // Mint Illuminate zero coupons
        IERC5095(principalToken(u, m)).authMint(msg.sender, received);

        emit Lend(p, u, m, received, a, msg.sender);
        return received;
    }
```

Sense lend() also directly calls user-supplied AMM `x` and mints the balance difference to a caller:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L681-L741

```solidity
    /// @notice lend method signature for Sense
    /// @dev this method can be called before maturity to lend to Sense while minting Illuminate tokens
    /// @dev Sense provides a [divider] contract that splits [target] assets (underlying) into PTs and YTs. Each [target] asset has a [series] of contracts, each identifiable by their [maturity].
    /// @param p principal value according to the MarketPlace's Principals Enum
    /// @param u address of an underlying asset
    /// @param m maturity (timestamp) of the market
    /// @param a amount of underlying tokens to lend
    /// @param r slippage limit, minimum amount to PTs to buy
    /// @param x AMM that is used to conduct the swap
    /// @param s Sense's maturity for the given market
    /// @param adapter Sense's adapter necessary to facilitate the swap
    /// @return uint256 the amount of principal tokens lent out
    function lend(
        uint8 p,
        address u,
        uint256 m,
        uint128 a,
        uint256 r,
        address x,
        uint256 s,
        address adapter
    ) external unpaused(u, m, p) returns (uint256) {
        // Retrieve the principal token for this market
        IERC20 token = IERC20(IMarketPlace(marketPlace).token(u, m, p));

        // Transfer funds from user to Illuminate
        Safe.transferFrom(IERC20(u), msg.sender, address(this), a);

        // Determine the fee
        uint256 fee = a / feenominator;

        // Add the accumulated fees to the total
        fees[u] = fees[u] + fee;

        // Determine lent amount after fees
        uint256 lent = a - fee;

        // Stores the amount of principal tokens received in swap for underlying
        uint256 received;
        {
            // Get the starting balance of the principal token
            uint256 starting = token.balanceOf(address(this));

            // Swap those tokens for the principal tokens
            ISensePeriphery(x).swapUnderlyingForPTs(adapter, s, lent, r);

            // Calculate number of principal tokens received in the swap
            received = token.balanceOf(address(this)) - starting;

            // Verify that we received the principal tokens
            if (received < r) {
                revert Exception(11, 0, 0, address(0), address(0));
            }
        }

        // Mint the Illuminate tokens based on the returned amount
        IERC5095(principalToken(u, m)).authMint(msg.sender, received);

        emit Lend(p, u, m, received, a, msg.sender);
        return received;
    }
``` 

## Tool used

Manual Review

## Recommendation

Consider adding reentracy guard modifier to Yield, Swivel, Element, APWine and Sense lend() functions of the Lender.

Notice that although Pendle, Tempus and Notional versions of lend() look to be resilient to the attack as they use either internal address (Pendle and Notional) or verify the supplied address (Tempus, https://github.com/tempus-finance/fixed-income-protocol/blob/master/contracts/TempusController.sol#L63) the same reentracy guard modifier can be used there as well as a general approach as these functions still mint the recorded balance difference to a user and there might exist yet unnoticed possibility to game it.

In all these cases either direct removal of the attack surface or precautious control for it do justify the reentracy guard gas cost.