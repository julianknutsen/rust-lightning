use bitcoin::secp256k1;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{SecretKey, PublicKey};

use ln::peers::handshake::hash::HandshakeHash;
use ln::peers::handshake::acts::{Act, ActOne, ACT_ONE_LENGTH, ActTwo, ACT_TWO_LENGTH, ACT_THREE_LENGTH, ActThree};
use ln::peers::handshake::states::HandshakeState2::{AwaitingActTwo2, AwaitingActThree2, Complete2};
use ln::peers::{chacha, hkdf};
use ln::peers::conduit::{Conduit, SymmetricKey};

pub enum HandshakeState2 {
	Uninitiated2(UninitiatedHandshakeState),
	AwaitingActOne2(AwaitingActOneHandshakeState),
	AwaitingActTwo2(AwaitingActTwoHandshakeState),
	AwaitingActThree2(AwaitingActThreeHandshakeState),
	Complete2(Option<(Conduit, PublicKey)>),
}

impl HandshakeState2 {
	pub(crate) fn next(self, input: &[u8]) -> Result<(Option<Act>, HandshakeState2), String> {
		match self {
			HandshakeState2::Uninitiated2(state) => { state.next(input) },
			HandshakeState2::AwaitingActOne2(state) => { state.next(input) },
			HandshakeState2::AwaitingActTwo2(state) => { state.next(input) },
			HandshakeState2::AwaitingActThree2(state) => { state.next(input) },
			HandshakeState2::Complete2(_conduit) => { panic!("no acts left to process") }
		}
	}
}

trait IHandshakeState {
	fn next(self, input: &[u8]) -> Result<(Option<Act>, HandshakeState2), String>;
}

pub struct UninitiatedHandshakeState {
	initiator_private_key: SecretKey,
	initiator_ephemeral_private_key: SecretKey,
	responder_public_key: PublicKey,
}

pub struct AwaitingActOneHandshakeState {
	responder_private_key: SecretKey,
	responder_ephemeral_private_key: SecretKey,
	chaining_key: [u8; 32],
	hash: HandshakeHash,
	read_buffer: Vec<u8>
}

pub struct AwaitingActTwoHandshakeState {
	initiator_private_key: SecretKey,
	initiator_ephemeral_private_key: SecretKey,
	responder_public_key: PublicKey,
	chaining_key: [u8; 32],
	hash: HandshakeHash,
	read_buffer: Vec<u8>
}

pub struct AwaitingActThreeHandshakeState {
	hash: HandshakeHash,
	responder_ephemeral_private_key: SecretKey,
	chaining_key: [u8; 32],
	temporary_key: [u8; 32],
	read_buffer: Vec<u8>
}

impl UninitiatedHandshakeState {
	pub(crate) fn new(initiator_private_key: SecretKey, initiator_ephemeral_private_key: SecretKey, responder_public_key: PublicKey) -> Self {
		UninitiatedHandshakeState {
			initiator_private_key,
			initiator_ephemeral_private_key,
			responder_public_key
		}
	}
}

impl IHandshakeState for UninitiatedHandshakeState {
	fn next(self, _input: &[u8]) -> Result<(Option<Act>, HandshakeState2), String> {

		let initiator_private_key = self.initiator_private_key;
		let initiator_ephemeral_private_key = self.initiator_ephemeral_private_key;
		let responder_public_key = self.responder_public_key;

		let (mut hash, chaining_key) = handshake_state_initialization(&responder_public_key);

		// serialize act one
		let (act_one, chaining_key, _) = calculate_act_message(
			&initiator_ephemeral_private_key,
			&responder_public_key,
			chaining_key,
			&mut hash,
		);

		Ok((
			Some(Act::One(ActOne(act_one))),
			AwaitingActTwo2(AwaitingActTwoHandshakeState::new(initiator_private_key, initiator_ephemeral_private_key, responder_public_key, chaining_key, hash))
		))
	}
}

impl AwaitingActOneHandshakeState {
	pub(crate) fn new(responder_private_key: SecretKey, responder_ephemeral_private_key: SecretKey) -> Self {

		let curve = secp256k1::Secp256k1::new();
		let responder_public_key = PublicKey::from_secret_key(&curve, &responder_private_key);
		let (hash, chaining_key) = handshake_state_initialization(&responder_public_key);

		AwaitingActOneHandshakeState {
			responder_private_key,
			responder_ephemeral_private_key,
			chaining_key,
			hash,
			read_buffer: Vec::new()
		}
	}
}

impl IHandshakeState for AwaitingActOneHandshakeState {
	fn next(self, input: &[u8]) -> Result<(Option<Act>, HandshakeState2), String> {

		let mut read_buffer = self.read_buffer;
		read_buffer.extend_from_slice(input);

		if read_buffer.len() < ACT_ONE_LENGTH {
			return Err("need at least 50 bytes".to_string());
		}

		let mut hash = self.hash;
		let responder_private_key = self.responder_private_key;
		let chaining_key = self.chaining_key;
		let responder_ephemeral_private_key = self.responder_ephemeral_private_key;

		// common functions take in an array so drain here for now
		let mut act_one_bytes = [0u8; ACT_ONE_LENGTH];
		act_one_bytes.copy_from_slice(&read_buffer[..ACT_ONE_LENGTH]);
		read_buffer.drain(..ACT_ONE_LENGTH);

		let (initiator_ephemeral_public_key, chaining_key, _) = process_act_message(
			act_one_bytes,
			&responder_private_key,
			chaining_key,
			&mut hash,
		)?;

		let (act_two, chaining_key, temporary_key) = calculate_act_message(
			&responder_ephemeral_private_key,
			&initiator_ephemeral_public_key,
			chaining_key,
			&mut hash,
		);

		Ok((
			Some(Act::Two(ActTwo(act_two))),
			AwaitingActThree2(
				AwaitingActThreeHandshakeState::new(hash, responder_ephemeral_private_key, chaining_key, temporary_key, read_buffer)
			)
		))
	}
}

impl IHandshakeState for AwaitingActTwoHandshakeState {
	fn next(self, input: &[u8]) -> Result<(Option<Act>, HandshakeState2), String> {

		let mut read_buffer = self.read_buffer;
		read_buffer.extend_from_slice(input);

		if read_buffer.len() < ACT_TWO_LENGTH {
			return Err("need at least 50 bytes".to_string());
		}

		let initiator_private_key = self.initiator_private_key;
		let initiator_ephemeral_private_key = self.initiator_ephemeral_private_key;
		let responder_public_key = self.responder_public_key;
		let mut hash = self.hash;
		let chaining_key = self.chaining_key;

		// common functions take in an array so drain here for now
		let mut act_two_bytes = [0u8; ACT_TWO_LENGTH];
		act_two_bytes.copy_from_slice(&read_buffer[..ACT_TWO_LENGTH]);
		read_buffer.drain(..ACT_TWO_LENGTH);

		let (responder_ephemeral_public_key, chaining_key, temporary_key) = process_act_message(
			act_two_bytes,
			&initiator_ephemeral_private_key,
			chaining_key,
			&mut hash,
		)?;

		// start serializing act three

		let curve = secp256k1::Secp256k1::new();
		let initiator_public_key = PublicKey::from_secret_key(&curve, &initiator_private_key);
		let tagged_encrypted_pubkey = chacha::encrypt(&temporary_key, 1, &hash.value, &initiator_public_key.serialize());
		hash.update(&tagged_encrypted_pubkey);

		let ecdh = ecdh(&initiator_private_key, &responder_ephemeral_public_key);
		let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);
		let authentication_tag = chacha::encrypt(&temporary_key, 0, &hash.value, &[0; 0]);
		let (sending_key, receiving_key) = hkdf::derive(&chaining_key, &[0; 0]);

		let mut act_three = [0u8; ACT_THREE_LENGTH];
		act_three[1..50].copy_from_slice(&tagged_encrypted_pubkey);
		act_three[50..].copy_from_slice(authentication_tag.as_slice());

		let mut conduit = Conduit::new(sending_key, receiving_key, chaining_key);

		if read_buffer.len() > 0 { // have we received more data still?
			conduit.read(&read_buffer[..]);
			read_buffer.drain(..);
		}

		Ok((
			Some(Act::Three(ActThree(act_three))),
			Complete2(Some((conduit, responder_public_key)))
		))
	}
}

impl AwaitingActTwoHandshakeState {
	fn new(initiator_private_key: SecretKey, initiator_ephemeral_private_key: SecretKey, responder_public_key: PublicKey, chaining_key: [u8;32], hash: HandshakeHash) -> Self {
		AwaitingActTwoHandshakeState {
			initiator_private_key,
			initiator_ephemeral_private_key,
			responder_public_key,
			chaining_key,
			hash,
			read_buffer: Vec::new()
		}
	}
}

impl IHandshakeState for AwaitingActThreeHandshakeState {
	fn next(self, input: &[u8]) -> Result<(Option<Act>, HandshakeState2), String> {
		let mut read_buffer = self.read_buffer;
		read_buffer.extend_from_slice(input);

		if read_buffer.len() < ACT_THREE_LENGTH {
			return Err("need at least 66 bytes".to_string());
		}

		let mut hash = self.hash;
		let temporary_key = self.temporary_key;
		let responder_ephemeral_private_key = self.responder_ephemeral_private_key;
		let chaining_key = self.chaining_key;

		let mut act_three_bytes = [0u8; ACT_THREE_LENGTH];
		act_three_bytes.copy_from_slice(&read_buffer[..ACT_THREE_LENGTH]);
		read_buffer.drain(..ACT_THREE_LENGTH);

		let version = act_three_bytes[0];
		if version != 0 {
			// this should not crash the process, hence no panic
			return Err("unexpected version".to_string());
		}

		let mut tagged_encrypted_pubkey = [0u8; 49];
		tagged_encrypted_pubkey.copy_from_slice(&act_three_bytes[1..50]);

		let mut chacha_tag = [0u8; 16];
		chacha_tag.copy_from_slice(&act_three_bytes[50..66]);

		let remote_pubkey_vec = chacha::decrypt(&temporary_key, 1, &hash.value, &tagged_encrypted_pubkey)?;
		let mut initiator_pubkey_bytes = [0u8; 33];
		initiator_pubkey_bytes.copy_from_slice(remote_pubkey_vec.as_slice());
		let initiator_pubkey = if let Ok(public_key) = PublicKey::from_slice(&initiator_pubkey_bytes) {
			public_key
		} else {
			return Err("invalid remote public key".to_string());
		};

		hash.update(&tagged_encrypted_pubkey);

		let ecdh = ecdh(&responder_ephemeral_private_key, &initiator_pubkey);
		let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);
		let _tag_check = chacha::decrypt(&temporary_key, 0, &hash.value, &chacha_tag)?;
		let (receiving_key, sending_key) = hkdf::derive(&chaining_key, &[0; 0]);

		let mut conduit = Conduit::new(sending_key, receiving_key, chaining_key);

		if read_buffer.len() > 0 { // have we received more data still?
			conduit.read(&read_buffer[..]);
			read_buffer.drain(..);
		}

		Ok((
			None,
			Complete2(Some((conduit, initiator_pubkey)))
		))
	}
}

impl AwaitingActThreeHandshakeState {
	fn new(hash: HandshakeHash, responder_ephemeral_private_key: SecretKey, chaining_key: [u8; 32], temporary_key: [u8; 32], read_buffer: Vec<u8>) -> Self {
		AwaitingActThreeHandshakeState {
			hash,
			responder_ephemeral_private_key,
			chaining_key,
			temporary_key,
			read_buffer
		}
	}
}

// Generate a SHA-256 hash from one or more elements
macro_rules! sha256 {
	( $( $x:expr ),+ ) => {{
		let mut sha = Sha256::engine();
		$(
			sha.input($x.as_ref());
		)*
		Sha256::from_engine(sha).into_inner()
	}}
}

// Concatenate two slices in a Vec
macro_rules! concat {
	($arg1:expr, $arg2:expr) => {{
		let mut result = $arg1.to_vec();
		result.extend_from_slice($arg2.as_ref());
		result
	}}
}

// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#handshake-state-initialization
fn handshake_state_initialization(responder_public_key: &PublicKey) -> (HandshakeHash, [u8; 32]) {
	let protocol_name = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";
	let prologue = b"lightning";

	// 1. h = SHA-256(protocolName)
	// 2. ck = h
	let chaining_key = sha256!(protocol_name);

	// 3. h = SHA-256(h || prologue)
	let hash = sha256!(concat!(chaining_key, prologue));

	// h = SHA-256(h || responderPublicKey)
	let hash = sha256!(concat!(hash, responder_public_key.serialize()));

	let hash = HandshakeHash {
		value: hash
	};

	(hash, chaining_key)
}

fn calculate_act_message(local_private_key: &SecretKey, remote_public_key: &PublicKey, chaining_key: [u8; 32], hash: &mut HandshakeHash) -> ([u8; 50], SymmetricKey, SymmetricKey) {
	let local_public_key = private_key_to_public_key(local_private_key);

	hash.update(&local_public_key.serialize());

	let ecdh = ecdh(local_private_key, &remote_public_key);
	let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);
	let tagged_ciphertext = chacha::encrypt(&temporary_key, 0, &hash.value, &[0; 0]);

	hash.update(&tagged_ciphertext);

	let mut act = [0u8; 50];
	act[1..34].copy_from_slice(&local_public_key.serialize());
	act[34..].copy_from_slice(tagged_ciphertext.as_slice());

	(act, chaining_key, temporary_key)
}

// Due to the very high similarity of acts 1 and 2, this method is used to process both
fn process_act_message(act_bytes: [u8; 50], local_private_key: &SecretKey, chaining_key: SymmetricKey, hash: &mut HandshakeHash) -> Result<(PublicKey, SymmetricKey, SymmetricKey), String> {
	let version = act_bytes[0];
	if version != 0 {
		// this should not crash the process, hence no panic
		return Err("unexpected version".to_string());
	}

	let mut ephemeral_public_key_bytes = [0u8; 33];
	ephemeral_public_key_bytes.copy_from_slice(&act_bytes[1..34]);
	let ephemeral_public_key = if let Ok(public_key) = PublicKey::from_slice(&ephemeral_public_key_bytes) {
		public_key
	} else {
		return Err("invalid remote ephemeral public key".to_string());
	};

	let mut chacha_tag = [0u8; 16];
	chacha_tag.copy_from_slice(&act_bytes[34..50]);

	// process the act message

	// update hash with partner's pubkey
	hash.update(&ephemeral_public_key.serialize());

	// calculate ECDH with partner's pubkey and local privkey
	let ecdh = ecdh(local_private_key, &ephemeral_public_key);

	// HKDF(chaining key, ECDH) -> chaining key' + next temporary key
	let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);

	// Validate chacha tag (temporary key, 0, hash, chacha_tag)
	let _tag_check = chacha::decrypt(&temporary_key, 0, &hash.value, &chacha_tag)?;

	hash.update(&chacha_tag);

	Ok((ephemeral_public_key, chaining_key, temporary_key))
}

fn private_key_to_public_key(private_key: &SecretKey) -> PublicKey {
	let curve = secp256k1::Secp256k1::new();
	let pk_object = PublicKey::from_secret_key(&curve, &private_key);
	pk_object
}

fn ecdh(private_key: &SecretKey, public_key: &PublicKey) -> SymmetricKey {
	let curve = secp256k1::Secp256k1::new();
	let mut pk_object = public_key.clone();
	pk_object.mul_assign(&curve, &private_key[..]).expect("invalid multiplication");

	let preimage = pk_object.serialize();
	let mut sha = Sha256::engine();
	sha.input(preimage.as_ref());
	Sha256::from_engine(sha).into_inner()
}

#[cfg(test)]
mod test {
	use hex;

	use bitcoin::secp256k1;
	use bitcoin::secp256k1::{PublicKey, SecretKey};

	use ln::peers::handshake::acts::Act;
	use ln::peers::handshake::states::{UninitiatedHandshakeState, AwaitingActOneHandshakeState, HandshakeState2};
	use ln::peers::handshake::states::HandshakeState2::{AwaitingActThree2, AwaitingActTwo2, Complete2};

	struct TestCtx {
		initiator: HandshakeState2,
		initiator_public_key: PublicKey,
		responder: HandshakeState2,
		responder_public_key: PublicKey
	}

	impl TestCtx {
		fn new() -> Self {
			let curve = secp256k1::Secp256k1::new();
			let initiator_private_key = SecretKey::from_slice(&[0x_11_u8; 32]).unwrap();
			let initiator_public_key = PublicKey::from_secret_key(&curve, &initiator_private_key);
			let initiator_ephemeral_private_key = SecretKey::from_slice(&[0x_12_u8; 32]).unwrap();

			let responder_private_key = SecretKey::from_slice(&[0x_21_u8; 32]).unwrap();
			let responder_public_key = PublicKey::from_secret_key(&curve, &responder_private_key);
			let responder_ephemeral_private_key = SecretKey::from_slice(&[0x_22_u8; 32]).unwrap();

			let initiator = UninitiatedHandshakeState::new(initiator_private_key, initiator_ephemeral_private_key, responder_public_key);
			let responder = AwaitingActOneHandshakeState::new(responder_private_key, responder_ephemeral_private_key);

			TestCtx {
				initiator: HandshakeState2::Uninitiated2(initiator),
				initiator_public_key,
				responder: HandshakeState2::AwaitingActOne2(responder),
				responder_public_key,
			}
		}
	}

	macro_rules! do_next_or_panic {
		($state:expr, $input:expr) => {
			if let (Some(output_act), next_state) = $state.next($input).unwrap() {
				(output_act.serialize(), next_state)
			} else {
				panic!();
			}
		}
	}

	macro_rules! assert_matches {
		($e:expr, $state_match:pat) => {
			match $e {
				$state_match => (),
				_ => panic!()
			}
		}
	}

	// Initiator::Uninitiated -> AwaitingActTwo
	#[test]
	fn uninitiated_to_awaiting_act_two() {
		let test_ctx = TestCtx::new();

		assert_matches!(test_ctx.initiator.next(&[]).unwrap(), (Some(Act::One(_)), AwaitingActTwo2(_)));
	}

	// Initiator::Uninitiated -> AwaitingActTwo (extra bytes in argument)
	#[test]
	fn uninitiated_to_awaiting_act_two_extra_bytes() {
		let test_ctx = TestCtx::new();

		assert_matches!(test_ctx.initiator.next(&[1]).unwrap(), (Some(Act::One(_)), AwaitingActTwo2(_)));
	}

	// Responder::AwaitingActOne -> Error (input too small)
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_input_too_small() {
		let test_ctx = TestCtx::new();
		assert_eq!(test_ctx.responder.next(&[]).err(), Some(String::from("need at least 50 bytes")))
	}

	// Responder::AwaitingActOne -> AwaitingActThree
	// TODO: Should this fail since we don't expect data > ACT_ONE_LENGTH and likely indicates
	// a bad peer?
	// TODO: Should the behavior be changed to handle act1 data that is striped across multiple
	// next() calls?
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_input_extra_bytes() {
		let test_ctx = TestCtx::new();
		let (mut act1, _) = do_next_or_panic!(test_ctx.initiator, &[]);
		act1.extend_from_slice(&[1]);

		assert_matches!(test_ctx.responder.next(&act1).unwrap(), (Some(Act::Two(_)), AwaitingActThree2(_)));
	}

	// Responder::AwaitingActOne -> Error (bad version byte)
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_input_bad_version() {
		let test_ctx = TestCtx::new();
		let (mut act1, _) = do_next_or_panic!(test_ctx.initiator, &[]);
		// set version byte to 1
		act1[0] = 1;

		assert_eq!(test_ctx.responder.next(&act1).err(), Some(String::from("unexpected version")));
	}

	// Responder::AwaitingActOne -> Error (invalid hmac)
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_invalid_hmac() {
		let test_ctx = TestCtx::new();
		// Modify the initiator to point to a different responder
		let (mut act1, _) = do_next_or_panic!(test_ctx.initiator, &[]);
		// corrupt the ciphertext
		act1[34] = 0;

		assert_eq!(test_ctx.responder.next(&act1).err(), Some(String::from("invalid hmac")));
	}

	// Responder::AwaitingActOne -> Error (invalid remote ephemeral key)
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_invalid_remote_ephemeral_key() {
		let test_ctx = TestCtx::new();
		// Modify the initiator to point to a different responder
		let (mut act1, _) = do_next_or_panic!(test_ctx.initiator, &[]);
		// corrupt the ephemeral public key
		act1[1] = 0;

		assert_eq!(test_ctx.responder.next(&act1).err(), Some(String::from("invalid remote ephemeral public key")));
	}

	// Responder::AwaitingActOne -> AwaitingActThree
	#[test]
	fn awaiting_act_one_to_awaiting_act_three() {
		let test_ctx = TestCtx::new();
		let (act1, _) = do_next_or_panic!(test_ctx.initiator, &[]);

		assert_matches!(test_ctx.responder.next(&act1).unwrap(), (Some(Act::Two(_)), AwaitingActThree2(_)));
	}

	// Initiator::AwaitingActTwo -> Complete
	#[test]
	fn awaiting_act_two_to_complete() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);

		let remote_pubkey = if let (Some(Act::Three(_)), Complete2(Some((_, remote_pubkey)))) = awaiting_act_two_state.next(&act2).unwrap() {
			remote_pubkey
		} else {
			panic!();
		};

		assert_eq!(remote_pubkey, test_ctx.responder_public_key);
	}

	// Initiator::AwaitingActTwo -> Complete (with extra data)
	// Ensures that any remaining data in the read buffer is transferred to the conduit once
	// the handshake is complete
	// TODO: Is this valid? Don't we expect peers to need ActThree before sending additional data?
	#[test]
	fn awaiting_act_two_to_complete_excess_bytes_are_in_conduit() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (mut act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		act2.extend_from_slice(&[1; 100]);

		let (_act3, complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);

		let conduit = if let Complete2(Some((conduit, _))) = complete_state {
			conduit
		} else {
			panic!();
		};

		assert_eq!(100, conduit.decryptor.read_buffer_length());
	}

	// Initiator::AwaitingActTwo -> Error (input too small)
	#[test]
	fn awaiting_act_two_input_too_small() {
		let test_ctx = TestCtx::new();
		let (_act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);

		assert_eq!(awaiting_act_two_state.next(&[]).err(), Some(String::from("need at least 50 bytes")));
	}

	// Initiator::AwaitingActTwo -> Error (bad version byte)
	#[test]
	fn awaiting_act_two_bad_version_byte() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (mut act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		// set invalid version byte
		act2[0] = 1;

		assert_eq!(awaiting_act_two_state.next(&act2).err(), Some(String::from("unexpected version")));
	}

	// Initiator::AwaitingActTwo -> Error (invalid hmac)
	#[test]
	fn awaiting_act_two_invalid_hmac() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (mut act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		// corrupt the ciphertext
		act2[34] = 0;

		assert_eq!(awaiting_act_two_state.next(&act2).err(), Some(String::from("invalid hmac")));
	}

	// Initiator::AwaitingActTwo -> Error (invalid ephemeral public key)
	#[test]
	fn awaiting_act_two_invalid_ephemeral_public_key() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (mut act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		// corrupt the ephemeral public key
		act2[1] = 0;

		assert_eq!(awaiting_act_two_state.next(&act2).err(), Some(String::from("invalid remote ephemeral public key")));
	}

	// Responder::AwaitingActThree -> Complete
	#[test]
	fn awaiting_act_three_to_complete() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);

		let remote_pubkey = if let (None, Complete2(Some((_, remote_pubkey)))) = awaiting_act_three_state.next(&act3).unwrap() {
			remote_pubkey
		} else {
			panic!();
		};

		assert_eq!(remote_pubkey, test_ctx.initiator_public_key);
	}

	// Responder::AwaitingActThree -> None (with extra bytes)
	// Ensures that any remaining data in the read buffer is transferred to the conduit once
	// the handshake is complete
	#[test]
	fn awaiting_act_three_excess_bytes_after_complete_are_in_conduit() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (mut act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);
		act3.extend_from_slice(&[2; 100]);

		let conduit = if let (_, Complete2(Some((conduit, _)))) = awaiting_act_three_state.next(&act3).unwrap() {
			conduit
		} else {
			panic!();
		};

		assert_eq!(100, conduit.decryptor.read_buffer_length());
	}

	// Responder::AwaitingActThree -> Error (input too small)
	#[test]
	fn awaiting_act_three_input_too_small() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (act3, _complete) = do_next_or_panic!(awaiting_act_two_state, &act2);

		assert_eq!(awaiting_act_three_state.next(&act3[..65]).err(), Some(String::from("need at least 66 bytes")));
	}

	// Responder::AwaitingActThree -> Error (bad version bytes)
	#[test]
	fn awaiting_act_three_bad_version_bytes() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (mut act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);
		// set version byte to 1
		act3[0] = 1;

		assert_eq!(awaiting_act_three_state.next(&act3).err(), Some(String::from("unexpected version")));
	}

	// Responder::AwaitingActThree -> Error (invalid hmac)
	#[test]
	fn awaiting_act_three_invalid_hmac() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (mut act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);
		// corrupt encrypted pubkey
		act3[1] = 1;

		assert_eq!(awaiting_act_three_state.next(&act3).err(), Some(String::from("invalid hmac")));
	}

	// Responder::AwaitingActThree -> Error (invalid tag hmac)
	#[test]
	fn awaiting_act_three_invalid_tag_hmac() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (mut act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);
		// corrupt tag
		act3[50] = 1;

		assert_eq!(awaiting_act_three_state.next(&act3).err(), Some(String::from("invalid hmac")));
	}

	// Initiator::Complete -> Error
	#[test]
	#[should_panic(expected = "no acts left to process")]
	fn initiator_complete_next_fail() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (_act3, complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);

		complete_state.next(&[]).unwrap();
	}

	// Initiator::Complete -> Error
	#[test]
	#[should_panic(expected = "no acts left to process")]
	fn responder_complete_next_fail() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);

		let complete_state = if let (None, complete_state) = awaiting_act_three_state.next(&act3).unwrap() {
			complete_state
		} else {
			panic!();
		};

		complete_state.next(&[]).unwrap();
	}

	// Test the Act byte generation against known good hard-coded values in case the implementation
	// changes in a symmetric way that makes the other tests useless
	#[test]
	fn test_acts_against_reference_bytes() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);

		assert_eq!(hex::encode(&act1),
				   "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a");
		assert_eq!(hex::encode(&act2),
				   "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae");
		assert_eq!(hex::encode(&act3),
				   "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba");
	}
}
