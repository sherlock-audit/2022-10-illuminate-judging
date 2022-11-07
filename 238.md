hyh

high

# Unlimited mint of Illuminate PTs is possible whenever any market is uninitialized and unpaused

## Summary

If some market isn't defined, but not paused, which is true by default, an unlimited mint of Illuminate PTs is possible as `Safe.transferFrom(address(0), ...)` will be successful due to zero address check isn't performed for the token used, while low-level call to zero address is a success.

## Vulnerability Detail

Lender's mint do not check that principal obtained from `marketPlace` is a viable token. It can be zero address if `(u, m, p)` isn't yet defined for a particular `p`. In the same time `unpaused(u, m, p)` is true by default corresponding to the uninitialized state.

This way once the Lender contract enters the state where `marketPlace` is defined, but some market for some particular `p` isn't yet (this is what setPrincipal() is for, i.e. it's a valid use case), and it is not paused (which is by default, as pausing is a manual pause() call), Lender's mint() can be used to issue unlimited number of Illuminate PTs to the attacker.

Bob the attacker can setup a script to track such situations for a new Lender contracts. I.e. he can track setMarketPlace() calls and if there is a principal token `IMarketPlace(marketPlace).token(u, m, 0)` created, but some market for `p > 0` from `Principals` is undefined, but isn't paused, Bob runs Lender's mint and obtains any number of `IMarketPlace(marketPlace).token(u, m, 0)` for free.

## Impact

An attacker can obtain unlimited Illuminate PTs, subsequently stealing all the funds of any other users with Redeeder's Illuminate redeem(). Such overmint can be unnoticed as it doesn't interfere with any other operations in the system.

The situation described can be a part of normal system setup workflow, unless being specifically handled. The impact itself is full insolvency for a given `(u, m)`. This way setting the severity to be high.

## Code Snippet

If mint() be called with `p` such that `paused[u][m][p] == false` and Marketplace's `markets[u][m][p] == 0`, i.e. both are uninitialized yet, it unlimitedly mints Illuminate PTs for free:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L264-L288

```solidity
    /// @notice mint swaps the sender's principal tokens for Illuminate's ERC5095 tokens in effect, this opens a new fixed rate position for the sender on Illuminate
    /// @param p principal value according to the MarketPlace's Principals Enum
    /// @param u address of an underlying asset
    /// @param m maturity (timestamp) of the market
    /// @param a amount being minted
    /// @return bool true if the mint was successful
    function mint(
        uint8 p,
        address u,
        uint256 m,
        uint256 a
    ) external unpaused(u, m, p) returns (bool) {
        // Fetch the desired principal token
        address principal = IMarketPlace(marketPlace).token(u, m, p);

        // Transfer the users principal tokens to the lender contract
        Safe.transferFrom(IERC20(principal), msg.sender, address(this), a);

        // Mint the tokens received from the user
        IERC5095(principalToken(u, m)).authMint(msg.sender, a);

        emit Mint(p, u, m, a);

        return true;
    }
```

`principalToken(u, m)` is the Illuminate PT for the `(u, m)` pair:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L1047-L1053

```solidity
    /// @notice retrieves the ERC5095 token for the given market
    /// @param u address of an underlying asset
    /// @param m maturity (timestamp) of the market
    /// @return address of the ERC5095 token for the market
    function principalToken(address u, uint256 m) internal returns (address) {
        return IMarketPlace(marketPlace).token(u, m, 0);
    }
```

`IMarketPlace(marketPlace).token(u, m, p)` returns `markets[u][m][p]`:


https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Marketplace.sol#L601-L611

```solidity
    /// @notice provides an interface to receive principal token addresses from markets
    /// @param u address of an underlying asset
    /// @param m maturity (timestamp) of the market
    /// @param p principal value according to the MarketPlace's Principals Enum
    function token(
        address u,
        uint256 m,
        uint256 p
    ) external view returns (address) {
        return markets[u][m][p];
    }
```

`markets[u][m][p]` might be set or not set by createMarket() and setPrincipal(), there is no control for setup to be full in either of the functions:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Marketplace.sol#L120-L243

```solidity
    /// @notice creates a new market for the given underlying token and maturity
    /// @param u address of an underlying asset
    /// @param m maturity (timestamp) of the market
    /// @param t principal token addresses for this market
    /// @param n name for the Illuminate token
    /// @param s symbol for the Illuminate token
    /// @param e address of the Element vault that corresponds to this market
    /// @param a address of the APWine router that corresponds to this market
    /// @return bool true if successful
    function createMarket(
        address u,
        uint256 m,
        address[8] calldata t,
        string calldata n,
        string calldata s,
        address e,
        address a
    ) external authorized(admin) returns (bool) {
        {
            // Get the Illuminate principal token for this market (if one exists)
            address illuminate = markets[u][m][
                (uint256(Principals.Illuminate))
            ];

            // If illuminate PT already exists, a new market cannot be created
            if (illuminate != address(0)) {
                revert Exception(9, 0, 0, illuminate, address(0));
            }
        }

        // Create an Illuminate principal token for the new market
        address illuminateToken = address(
            new ERC5095(
                u,
                m,
                redeemer,
                lender,
                address(this),
                n,
                s,
                IERC20(u).decimals()
            )
        );

        {
            // create the principal tokens array
            address[9] memory market = [
                illuminateToken, // Illuminate
                t[0], // Swivel
                t[1], // Yield
                t[2], // Element
                t[3], // Pendle
                t[4], // Tempus
                t[5], // Sense
                t[6], // APWine
                t[7] // Notional
            ];

            // Set the market
            markets[u][m] = market;

            ...

            emit CreateMarket(u, m, market, e, a);
        }
        return true;
    }

    /// @notice allows the admin to set an individual market
    /// @param p principal value according to the MarketPlace's Principals Enum
    /// @param u address of an underlying asset
    /// @param m maturity (timestamp) of the market
    /// @param a address of the new principal token
    /// @return bool true if the principal set, false otherwise
    function setPrincipal(
        uint8 p,
        address u,
        uint256 m,
        address a
    ) external authorized(admin) returns (bool) {
        // Get the current principal token for the principal token being set
        address market = markets[u][m][p];

        // Verify that it has not already been set
        if (market != address(0)) {
            revert Exception(9, 0, 0, market, address(0));
        }

        // Set the principal token in the markets mapping
        markets[u][m][p] = a;

        ...

        emit SetPrincipal(u, m, a, p);
        return true;
    }
```

Bob can track setMarketPlace() calls:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L249-L262

```solidity
    /// @notice sets the address of the marketplace contract which contains the addresses of all the fixed rate markets
    /// @param m the address of the marketplace contract
    /// @return bool true if the address was set
    function setMarketPlace(address m)
        external
        authorized(admin)
        returns (bool)
    {
        if (marketPlace != address(0)) {
            revert Exception(5, 0, 0, marketPlace, address(0));
        }
        marketPlace = m;
        return true;
    }
```

Observing that `marketPlace` and `IMarketPlace(marketPlace).token(u, m, 0)` are set, Bob can call mint() to obtain Illuminate PTs for a given `(u, m)`.

To check that current Safe does call zero address successfully please see the POC (it's basically tenderly start script with `IERC20` and `Safe` copied over):

https://sandbox.tenderly.co/dmitriia/safe-transfer-zero

## Tool used

Manual Review

## Recommendation

As Lender's mint() might be not the only instance where the absence of token existence check opens up this attack surface, consider requiring token address to have code in all Safe operations.

Also, controlling that PT address obtained isn't zero is advised in all the instances where is it used, for example:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Lender.sol#L264-L288

```solidity
    /// @notice mint swaps the sender's principal tokens for Illuminate's ERC5095 tokens in effect, this opens a new fixed rate position for the sender on Illuminate
    /// @param p principal value according to the MarketPlace's Principals Enum
    /// @param u address of an underlying asset
    /// @param m maturity (timestamp) of the market
    /// @param a amount being minted
    /// @return bool true if the mint was successful
    function mint(
        uint8 p,
        address u,
        uint256 m,
        uint256 a
    ) external unpaused(u, m, p) returns (bool) {
        // Fetch the desired principal token
        address principal = IMarketPlace(marketPlace).token(u, m, p);

+	if (principal == address(0)) revert Exception(1, p, 0, address(0), address(0));  // same Exception as paused, as an example

        // Transfer the users principal tokens to the lender contract
        Safe.transferFrom(IERC20(principal), msg.sender, address(this), a);

        // Mint the tokens received from the user
        IERC5095(principalToken(u, m)).authMint(msg.sender, a);

        emit Mint(p, u, m, a);

        return true;
    }
```