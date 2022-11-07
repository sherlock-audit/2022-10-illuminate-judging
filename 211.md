hyh

high

# No returning of premium if there is no swap to PT

## Summary

Swivel version of Lender's lend() has optional premium conversion parameter. If it is set, the underlying funds are swapped to Swivel PTs and Illuminate PTs are minted to the caller. If it is not set, the underlying funds resulted from filling of the Swivel orders are left on the Lender's balance and are lost to the caller.

## Vulnerability Detail

There is no code covering the case of not swapping the underlying funds originated from execution of the Swivel orders. All such funds become irretrievable for the user after lend() with `e == false` call. Subsequent lend() calls will record current balance, that will include the previously realized underlying premium, as a staring point.

Notice that this is not a user mistake as lend() call without swap of the resulting premium to PT if a valid option, i.e. a user might want to obtain some Swivel PTs from the orders execution and have the premium back as a separate matter, there is no internal link between the two. lend() description also states that swapping is just an option.

## Impact

Net impact for the user is underlying fund freeze. The funds can be retrieved thereafter via administrative withdraw(), but as volume of operations will grow over time such manual accounting become less and less feasible, up to be operationally impossible, i.e. up to loss of these funds to the user.

As there is no low probability assumptions, i.e. the funds are being frozen as a part of the ordinary use case, setting the severity to be high.

## Code Snippet

Swivel lend() allows for optionally swapping the net underlying funds resulting from the filled Swivel orders to Swivel PTs:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L349-L370

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
```

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L407-L435

```solidity
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
```

However, if this swap doesn't take place, i.e. when `e` being false, the corresponding underlying amount is left on Lender's balance and becomes inaccessible for the user.

It can only be rescued manually with admin's withdraw():

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L831-L852

```solidity
    /// @notice allows the admin to withdraw the given token, provided the holding period has been observed
    /// @param e Address of token to withdraw
    /// @return bool true if successful
    function withdraw(address e) external authorized(admin) returns (bool) {
        uint256 when = withdrawals[e];
        if (when == 0) {
            revert Exception(18, 0, 0, address(0), address(0));
        }

        if (block.timestamp < when) {
            revert Exception(19, 0, 0, address(0), address(0));
        }

        delete withdrawals[e];

        delete fees[e];

        IERC20 token = IERC20(e);
        Safe.transfer(token, admin, token.balanceOf(address(this)));

        return true;
    }
```

## Tool used

Manual Review

## Recommendation

Consider returning the funds originated from Swivel orders execution back to the caller if no underlying to PT swap is requested:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L417-L424

```solidity
+               // Calculate the premium
+               uint256 premium = IERC20(u).balanceOf(address(this)) -
+                   starting;
+               if (premium > 0)
                   if (e) {
-                      // Calculate the premium
-                      uint256 premium = IERC20(u).balanceOf(address(this)) -
-                          starting;

                       // Swap the premium for Illuminate principal tokens
                       swivelLendPremium(u, m, y, premium, premiumSlippage);
-                  }
+                  } else {
+		       // Return the premium if not swapping
+		       Safe.transferFrom(IERC20(u), address(this), msg.sender, premium);
+                  }
```