//! Venue verification: is this `Swap` emitter really a pair a known factory
//! deployed?
//!
//! A Uniswap-V2-style factory deploys each pair with `CREATE2`, salted by the
//! sorted token pair, so a pair's address is a pure function of
//! `(factory, token0, token1, init_code_hash)`. Recomputing it and comparing
//! is proof the contract is the factory's pair for exactly those tokens, with
//! no call to trust. Asking the contract for its `factory()` would not be:
//! a spoofed pool answers whatever it likes.

use alloy_primitives::{keccak256, Address, B256};

/// A V2-style venue: a factory and the init code hash its pairs share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Venue {
    pub name: String,
    pub factory: Address,
    pub init_code_hash: B256,
}

impl V2Venue {
    /// The address this factory deploys the `(token_a, token_b)` pair at, in
    /// either token order.
    pub fn pair_address(&self, token_a: Address, token_b: Address) -> Address {
        let (token0, token1) = if token_a < token_b {
            (token_a, token_b)
        } else {
            (token_b, token_a)
        };
        let mut packed = [0u8; 40];
        packed[..20].copy_from_slice(token0.as_slice());
        packed[20..].copy_from_slice(token1.as_slice());
        self.factory.create2(keccak256(packed), self.init_code_hash)
    }

    /// Whether `pool` is this venue's pair for `(token0, token1)`. The pair
    /// contract orders its tokens, so a claimed order that is not ascending is
    /// a contract that is not a V2 pair.
    pub fn deployed(&self, pool: Address, token0: Address, token1: Address) -> bool {
        token0 < token1 && self.pair_address(token0, token1) == pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    fn uniswap() -> V2Venue {
        V2Venue {
            name: "uniswap-v2".into(),
            factory: address!("5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"),
            init_code_hash: b256!(
                "96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f"
            ),
        }
    }

    const USDC: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    const WETH: Address = address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    /// The real mainnet USDC/WETH Uniswap V2 pair.
    const USDC_WETH: Address = address!("B4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc");

    #[test]
    fn the_mainnet_usdc_weth_pair_is_derived_exactly() {
        assert_eq!(uniswap().pair_address(USDC, WETH), USDC_WETH);
        assert_eq!(uniswap().pair_address(WETH, USDC), USDC_WETH, "order-free");
    }

    #[test]
    fn a_spoofed_or_misordered_pool_is_not_deployed() {
        let v = uniswap();
        assert!(v.deployed(USDC_WETH, USDC, WETH));
        assert!(
            !v.deployed(USDC_WETH, WETH, USDC),
            "a real pair orders its tokens"
        );
        assert!(!v.deployed(Address::repeat_byte(0xCC), USDC, WETH));
        let other = V2Venue {
            init_code_hash: B256::repeat_byte(1),
            ..uniswap()
        };
        assert!(!other.deployed(USDC_WETH, USDC, WETH));
    }
}
