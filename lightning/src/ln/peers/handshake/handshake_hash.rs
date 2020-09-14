/// Abstraction for the hash digest used in the NOISE handshake
/// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;

pub(super) struct HandshakeHash {
	pub(super) value: [u8; 32],
}

impl HandshakeHash {
	// Initialize a new handshake_hash with the input data
	pub(super) fn new(first_input: &[u8]) -> Self {
		Self {
			value: Sha256::hash(first_input).into_inner()
		}
	}

	// Update the handshake hash with new data
	pub(super) fn update(&mut self, input: &[u8]) {
		let mut sha = Sha256::engine();
		sha.input(&self.value);
		sha.input(input);
		self.value = Sha256::from_engine(sha).into_inner();
	}
}
