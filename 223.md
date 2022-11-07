hyh

medium

# Converter cannot be changed in Redeemer

## Summary

Redeemer's setConverter() can be used to switch the converter contract, for example when new type of interest bearing token is introduced as Converter employs hard coded logic to deal with various types of IBTs. However new converter cannot be functional as there is no way to introduce the approvals needed, it can be done only once.

## Vulnerability Detail

Upgrading the converter contract is not fully implemented as switching the address without providing approvals isn’t sufficient, while it is the only action that can be done now.

## Impact

If there are some issues with converter or IBTs it covers there will not be possible to upgrade the contract.

Also, as currently the converter uses hard coded logic to cover Compound, Aave and Lido only, any new IBT cannot be introduced to the system as it requires new Converter to be rolled out for that.

Given that substantial part of Redeemer's logic is dependent on Converter's exchange from IBT to underlying that means the net impact can be up to massive fund freeze.

## Code Snippet

setConverter() allows for changing the converter contract:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L145-L152

```solidity
    /// @notice sets the converter address
    /// @param c address of the new converter
    /// @return bool true if successful
    function setConverter(address c) external authorized(admin) returns (bool) {
        converter = c;
        emit SetConverter(c);
        return true;
    }
```

approve() can provide the approvals needed, but it's `marketPlace` only:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Redeemer.sol#L201-L207

```solidity
    /// @notice approves the converter to spend the compounding asset
    /// @param i an interest bearing token that must be approved for conversion
    function approve(address i) external authorized(marketPlace) {
        if (i != address(0)) {
            Safe.approve(IERC20(i), address(converter), type(uint256).max);
        }
    }
```

And there `approve` is run solely on the new market introduction, via createMarket():

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Marketplace.sol#L120-L201

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
            	...
            )
        );

        {
        	...

            // Set the market
            markets[u][m] = market;

            // Have the lender contract approve the several contracts
            ILender(lender).approve(u, e, a, t[7]);

            // Have the redeemer contract approve the Pendle principal token
            if (t[3] != address(0)) {
                address underlyingYieldToken = IPendleToken(t[3])
                    .underlyingYieldToken();
                IRedeemer(redeemer).approve(underlyingYieldToken);
            }

            if (t[6] != address(0)) {
                address futureVault = IAPWineToken(t[6]).futureVault();
                address interestBearingToken = IAPWineFutureVault(futureVault)
                    .getIBTAddress();
                IRedeemer(redeemer).approve(interestBearingToken);
            }

            emit CreateMarket(u, m, market, e, a);
        }
        return true;
    }
```

And via setPrincipal():

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Marketplace.sol#L203-L243

```solidity
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

        if (p == uint8(Principals.Pendle)) {
            // Principal token must be approved for Pendle's redeem
            address underlyingYieldToken = IPendleToken(a)
                .underlyingYieldToken();
            IRedeemer(redeemer).approve(underlyingYieldToken);
        } else if (p == uint8(Principals.Apwine)) {
            address futureVault = IAPWineToken(a).futureVault();
            address interestBearingToken = IAPWineFutureVault(futureVault)
                .getIBTAddress();
            IRedeemer(redeemer).approve(interestBearingToken);
        } else if (p == uint8(Principals.Notional)) {
            // Principal token must be approved for Notional's lend
            ILender(lender).approve(address(0), address(0), address(0), a);
        }

        emit SetPrincipal(u, m, a, p);
        return true;
    }
```

In both cases it's required that either Illuminate or `market` is `address(0)`, i.e. both functions cannot be run repeatedly.

I.e. it's impossible to run approve if the market exists, so there is no way to approve and use new Converter as without approval it will not be functional, the corresponding Redeemer functions will be reverting as it's expected that converter can pull funds out of Redeemer.

Currently Converter functionality is fixed to deal with 3 types of IBTs:

https://github.com/sherlock-audit/2022-10-illuminate/blob/main/src/Converter.sol#L21-L51

```solidity
    function convert(
        address c,
        address u,
        uint256 a
    ) external {
        // first receive the tokens from msg.sender
        Safe.transferFrom(IERC20(c), msg.sender, address(this), a);

        // get Aave pool
        try IAaveAToken(c).POOL() returns (address pool) {
            // Allow the pool to spend the funds
            Safe.approve(IERC20(u), pool, a);
            // withdraw from Aave
            IAaveLendingPool(pool).withdraw(u, a, msg.sender);
        } catch {
            // attempt to redeem compound tokens to the underlying asset
            try ICompoundToken(c).redeem(a) {
                // get the balance of underlying assets redeemed
                uint256 balance = IERC20(u).balanceOf(address(this));
                // transfer the underlying back to the user
                Safe.transfer(IERC20(u), msg.sender, balance);
            } catch {
                // get the current balance of wstETH
                uint256 balance = IERC20(c).balanceOf(address(this));
                // unwrap wrapped staked eth
                uint256 unwrapped = ILido(c).unwrap(balance);
                // Send the unwrapped staked ETH to the caller
                Safe.transfer(IERC20(u), msg.sender, unwrapped);
            }
        }
    }
```

## Tool used

Manual Review

## Recommendation

Consider running the approvals setting on the introduction of the new Converter, i.e. run Marketplace's createMarket() approval logic as a part of Redeemer's setConverter(), also clearing the approvals for the old one.