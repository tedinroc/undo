//! P2WSH addresses in bech32 (BIP-173). Witness version 0 only, the only one this product creates.

use crate::Error;

/// A Bitcoin network Undo can name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Network {
    /// Bitcoin mainnet, real coins.
    Mainnet,
    /// Mutinynet, a signet with 30-second blocks.
    Mutinynet,
    /// Standard signet.
    Signet,
    /// Testnet4.
    Testnet4,
    /// A local regtest node.
    Regtest,
}

impl Network {
    /// The name used in the recovery file.
    pub fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Mutinynet => "mutinynet",
            Network::Signet => "signet",
            Network::Testnet4 => "testnet4",
            Network::Regtest => "regtest",
        }
    }

    /// The reverse of [`Network::name`].
    pub fn from_name(name: &str) -> Result<Self, Error> {
        [Network::Mainnet, Network::Mutinynet, Network::Signet, Network::Testnet4, Network::Regtest]
            .into_iter()
            .find(|n| n.name() == name)
            .ok_or(Error::BadNetwork)
    }

    /// The bech32 prefix. Mutinynet, signet and testnet4 all use `tb`, so an address alone does
    /// not say which test network a coin is on.
    pub fn hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "bc",
            Network::Mutinynet | Network::Signet | Network::Testnet4 => "tb",
            Network::Regtest => "bcrt",
        }
    }
}

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk = 1u32;
    for v in values {
        let top = chk >> 25;
        chk = (chk & 0x01ff_ffff) << 5 ^ u32::from(*v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// The address for a witness program of version 0.
pub fn p2wsh_address(network: Network, program: &[u8; 32]) -> String {
    let hrp = network.hrp().as_bytes();

    // Version 0, then the program regrouped from 8 bits to 5, padded with zero bits at the end.
    let mut data = Vec::with_capacity(59);
    data.push(0u8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in program {
        acc = acc << 8 | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data.push(((acc >> bits) & 31) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        data.push(((acc << (5 - bits)) & 31) as u8);
    }

    let mut expanded = Vec::with_capacity(hrp.len() * 2 + 1 + data.len() + 6);
    expanded.extend(hrp.iter().map(|c| c >> 5));
    expanded.push(0);
    expanded.extend(hrp.iter().map(|c| c & 31));
    expanded.extend_from_slice(&data);
    expanded.extend_from_slice(&[0; 6]);
    let check = polymod(&expanded) ^ 1;

    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(network.hrp());
    out.push('1');
    for d in &data {
        out.push(CHARSET[*d as usize] as char);
    }
    for i in 0..6 {
        out.push(CHARSET[((check >> (5 * (5 - i))) & 31) as usize] as char);
    }
    out
}
