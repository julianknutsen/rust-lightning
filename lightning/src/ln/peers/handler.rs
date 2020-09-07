//! Top level peer message handling and socket handling logic lives here.
//!
//! Instead of actually servicing sockets ourselves we require that you implement the
//! SocketDescriptor interface and use that to receive actions which you should perform on the
//! socket, and call into PeerManager with bytes read from the socket. The PeerManager will then
//! call into the provided message handlers (probably a ChannelManager and NetGraphmsgHandler) with messages
//! they should handle, and encoding/sending response messages.

use bitcoin::secp256k1::key::{SecretKey,PublicKey};

use ln::features::InitFeatures;
use ln::msgs;
use ln::msgs::{ChannelMessageHandler, LightningError, RoutingMessageHandler};
use ln::channelmanager::{SimpleArcChannelManager, SimpleRefChannelManager};
use util::ser::{Writeable};
use ln::wire;
use ln::wire::{Encode, Message};
use util::byte_utils;
use util::events::{MessageSendEvent, MessageSendEventsProvider};
use util::logger::Logger;
use routing::network_graph::NetGraphMsgHandler;

use std::collections::{HashMap,hash_map,HashSet};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{cmp,error,hash,fmt};
use std::ops::Deref;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256::HashEngine as Sha256Engine;
use bitcoin::hashes::{HashEngine, Hash};
use ln::peers::outbound_queue::OutboundQueue;
use ln::peers::transport::Transport;

const MSG_BUFF_SIZE: usize = 10;

/// Interface PeerHandler uses to interact with the Transport object
pub(super) trait ITransport {
	/// Instantiate the new outbound Transport
	fn new_outbound(initiator_static_private_key: &SecretKey, responder_static_public_key: &PublicKey, initiator_ephemeral_private_key: &SecretKey) -> Self;

	/// Set up the Transport receiving any bytes that need to be sent to the peer
	fn set_up_outbound(&mut self) -> Vec<u8>;

	/// Instantiate a new inbound Transport
	fn new_inbound(responder_static_private_key: &SecretKey, responder_ephemeral_private_key: &SecretKey) -> Self;

	/// Process input data similar to reading it off a descriptor directly.
	fn process_input(&mut self, input: &[u8], output_buffer: &mut impl PayloadQueuer) -> Result<(), String>;

	/// Returns true if the connection is established and encrypted messages can be sent.
	fn is_connected(&self) -> bool;

	/// Returns the node_id of the remote node. Panics if not connected.
	fn get_their_node_id(&self) -> PublicKey;

	/// Returns all Messages that have been received and can be parsed by the Transport
	fn drain_messages<L: Deref>(&mut self, logger: L) -> Result<Vec<Message>, PeerHandleError> where L::Target: Logger;

	/// Encodes, encrypts, and enqueues a message to the outbound queue. Panics if the connection is
	/// not established yet.
	fn enqueue_message<M: Encode + Writeable, Q: PayloadQueuer, L: Deref>(&mut self, message: &M, output_buffer: &mut Q, logger: L) where L::Target: Logger;
}


/// Trait representing a container that allows enqueuing of Vec<[u8]>
pub(super) trait PayloadQueuer {
	/// Enqueue item to the queue
	fn push_back(&mut self, item: Vec<u8>);

	/// Returns true if the queue is empty
	fn is_empty(&self) -> bool;

	/// Returns the amount of available space in queue
	fn queue_space(&self) -> usize;
}

/// Implement &mut PayloadQueuer passthroughs
impl<'a, T> PayloadQueuer for &'a mut T where
	T: PayloadQueuer {
	fn push_back(&mut self, item: Vec<u8>) {
		T::push_back(self, item)
	}

	fn is_empty(&self) -> bool {
		T::is_empty(self)
	}

	fn queue_space(&self) -> usize {
		T::queue_space(self)
	}
}

/// Trait representing a container that can try to flush data through a SocketDescriptor
pub(super) trait SocketDescriptorFlusher {
	/// Write previously enqueued data to the SocketDescriptor. A return of false indicates the
	/// underlying SocketDescriptor could not fulfill the send_data() call and the blocked state
	/// has been set. Use unblock() when the SocketDescriptor may have more room.
	fn try_flush_one(&mut self, descriptor: &mut impl SocketDescriptor) -> bool;

	/// Clear the blocked state caused when a previous write failed
	fn unblock(&mut self);

	/// Check if the container is in a blocked state
	fn is_blocked(&self) -> bool;
}

/// Implement &mut Flushable passthroughs
impl<'a, T> SocketDescriptorFlusher for &'a mut T where
	T: SocketDescriptorFlusher {
	fn try_flush_one(&mut self, descriptor: &mut impl SocketDescriptor) -> bool {
		T::try_flush_one(self, descriptor)
	}

	fn unblock(&mut self) {
		T::unblock(self)
	}

	fn is_blocked(&self) -> bool {
		T::is_blocked(self)
	}
}

/// Provides references to trait impls which handle different types of messages.
pub struct MessageHandler<CM: Deref, RM: Deref> where
		CM::Target: ChannelMessageHandler,
		RM::Target: RoutingMessageHandler {
	/// A message handler which handles messages specific to channels. Usually this is just a
	/// ChannelManager object.
	pub chan_handler: CM,
	/// A message handler which handles messages updating our knowledge of the network channel
	/// graph. Usually this is just a NetGraphMsgHandlerMonitor object.
	pub route_handler: RM,
}

/// Provides an object which can be used to send data to and which uniquely identifies a connection
/// to a remote host. You will need to be able to generate multiple of these which meet Eq and
/// implement Hash to meet the PeerManager API.
///
/// For efficiency, Clone should be relatively cheap for this type.
///
/// You probably want to just extend an int and put a file descriptor in a struct and implement
/// send_data. Note that if you are using a higher-level net library that may call close() itself,
/// be careful to ensure you don't have races whereby you might register a new connection with an
/// fd which is the same as a previous one which has yet to be removed via
/// PeerManager::socket_disconnected().
pub trait SocketDescriptor : cmp::Eq + hash::Hash + Clone {
	/// Attempts to send some data from the given slice to the peer.
	///
	/// Returns the amount of data which was sent, possibly 0 if the socket has since disconnected.
	/// Note that in the disconnected case, socket_disconnected must still fire and further write
	/// attempts may occur until that time.
	///
	/// If the returned size is smaller than data.len(), a write_available event must
	/// trigger the next time more data can be written. Additionally, until the a send_data event
	/// completes fully, no further read_events should trigger on the same peer!
	///
	/// If a read_event on this descriptor had previously returned true (indicating that read
	/// events should be paused to prevent DoS in the send buffer), resume_read may be set
	/// indicating that read events on this descriptor should resume. A resume_read of false does
	/// *not* imply that further read events should be paused.
	fn send_data(&mut self, data: &[u8], resume_read: bool) -> usize;
	/// Disconnect the socket pointed to by this SocketDescriptor. Once this function returns, no
	/// more calls to write_buffer_space_avail, read_event or socket_disconnected may be made with
	/// this descriptor. No socket_disconnected call should be generated as a result of this call,
	/// though races may occur whereby disconnect_socket is called after a call to
	/// socket_disconnected but prior to socket_disconnected returning.
	fn disconnect_socket(&mut self);
}

/// Error for PeerManager errors. If you get one of these, you must disconnect the socket and
/// generate no further read_event/write_buffer_space_avail calls for the descriptor, only
/// triggering a single socket_disconnected call (unless it was provided in response to a
/// new_*_connection event, in which case no such socket_disconnected() must be called and the
/// socket silently disconencted).
pub struct PeerHandleError {
	/// Used to indicate that we probably can't make any future connections to this peer, implying
	/// we should go ahead and force-close any channels we have with it.
	pub no_connection_possible: bool,
}
impl fmt::Debug for PeerHandleError {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		formatter.write_str("Peer Sent Invalid Data")
	}
}
impl fmt::Display for PeerHandleError {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		formatter.write_str("Peer Sent Invalid Data")
	}
}
impl error::Error for PeerHandleError {
	fn description(&self) -> &str {
		"Peer Sent Invalid Data"
	}
}

enum InitSyncTracker{
	NoSyncRequested,
	ChannelsSyncing(u64),
	NodesSyncing(PublicKey),
}

struct Peer<TransportImpl: ITransport> {
	transport: TransportImpl,
	outbound: bool,
	their_features: Option<InitFeatures>,

	pending_outbound_buffer: OutboundQueue,

	sync_status: InitSyncTracker,

	awaiting_pong: bool,
}

impl<TransportImpl: ITransport> Peer<TransportImpl> {
	/// Returns true if the channel announcements/updates for the given channel should be
	/// forwarded to this peer.
	/// If we are sending our routing table to this peer and we have not yet sent channel
	/// announcements/updates for the given channel_id then we will send it when we get to that
	/// point and we shouldn't send it yet to avoid sending duplicate updates. If we've already
	/// sent the old versions, we should send the update, and so return true here.
	fn should_forward_channel_announcement(&self, channel_id: u64)->bool{
		match self.sync_status {
			InitSyncTracker::NoSyncRequested => true,
			InitSyncTracker::ChannelsSyncing(i) => i < channel_id,
			InitSyncTracker::NodesSyncing(_) => true,
		}
	}

	/// Similar to the above, but for node announcements indexed by node_id.
	fn should_forward_node_announcement(&self, node_id: PublicKey) -> bool {
		match self.sync_status {
			InitSyncTracker::NoSyncRequested => true,
			InitSyncTracker::ChannelsSyncing(_) => false,
			InitSyncTracker::NodesSyncing(pk) => pk < node_id,
		}
	}
}

struct PeerHolder<Descriptor: SocketDescriptor, TransportImpl: ITransport> {
	peers: HashMap<Descriptor, Peer<TransportImpl>>,
	/// Added to by do_read_event for cases where we pushed a message onto the send buffer but
	/// didn't call do_attempt_write_data to avoid reentrancy. Cleared in process_events()
	peers_needing_send: HashSet<Descriptor>,
	/// Only add to this set when noise completes:
	node_id_to_descriptor: HashMap<PublicKey, Descriptor>,
}

#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
fn _check_usize_is_32_or_64() {
	// See below, less than 32 bit pointers may be unsafe here!
	unsafe { mem::transmute::<*const usize, [u8; 4]>(panic!()); }
}

/// SimpleArcPeerManager is useful when you need a PeerManager with a static lifetime, e.g.
/// when you're using lightning-net-tokio (since tokio::spawn requires parameters with static
/// lifetimes). Other times you can afford a reference, which is more efficient, in which case
/// SimpleRefPeerManager is the more appropriate type. Defining these type aliases prevents
/// issues such as overly long function definitions.
pub type SimpleArcPeerManager<SD, M, T, F, C, L> = Arc<PeerManager<SD, SimpleArcChannelManager<M, T, F, L>, Arc<NetGraphMsgHandler<Arc<C>, Arc<L>>>, Arc<L>>>;

/// SimpleRefPeerManager is a type alias for a PeerManager reference, and is the reference
/// counterpart to the SimpleArcPeerManager type alias. Use this type by default when you don't
/// need a PeerManager with a static lifetime. You'll need a static lifetime in cases such as
/// usage of lightning-net-tokio (since tokio::spawn requires parameters with static lifetimes).
/// But if this is not necessary, using a reference is more efficient. Defining these type aliases
/// helps with issues such as long function definitions.
pub type SimpleRefPeerManager<'a, 'b, 'c, 'd, 'e, 'f, 'g, SD, M, T, F, C, L> = PeerManager<SD, SimpleRefChannelManager<'a, 'b, 'c, 'd, 'e, M, T, F, L>, &'e NetGraphMsgHandler<&'g C, &'f L>, &'f L>;

/// A PeerManager manages a set of peers, described by their SocketDescriptor and marshalls socket
/// events into messages which it passes on to its MessageHandlers.
///
/// Rather than using a plain PeerManager, it is preferable to use either a SimpleArcPeerManager
/// a SimpleRefPeerManager, for conciseness. See their documentation for more details, but
/// essentially you should default to using a SimpleRefPeerManager, and use a
/// SimpleArcPeerManager when you require a PeerManager with a static lifetime, such as when
/// you're using lightning-net-tokio.
pub struct PeerManager<Descriptor: SocketDescriptor, CM: Deref, RM: Deref, L: Deref> where
	CM::Target: ChannelMessageHandler,
	RM::Target: RoutingMessageHandler,
	L::Target: Logger {
		inner: PeerManagerImpl<Descriptor, CM, RM, L>,
}

struct PeerManagerImpl<Descriptor: SocketDescriptor, CM: Deref, RM: Deref, L: Deref, TransportImpl: ITransport=Transport> where
		CM::Target: ChannelMessageHandler,
		RM::Target: RoutingMessageHandler,
		L::Target: Logger {
	message_handler: MessageHandler<CM, RM>,
	peers: Mutex<PeerHolder<Descriptor, TransportImpl>>,
	our_node_secret: SecretKey,
	ephemeral_key_midstate: Sha256Engine,

	// Usize needs to be at least 32 bits to avoid overflowing both low and high. If usize is 64
	// bits we will never realistically count into high:
	peer_counter_low: AtomicUsize,
	peer_counter_high: AtomicUsize,

	logger: L,
}

enum MessageHandlingError {
	PeerHandleError(PeerHandleError),
	LightningError(LightningError),
}

impl From<PeerHandleError> for MessageHandlingError {
	fn from(error: PeerHandleError) -> Self {
		MessageHandlingError::PeerHandleError(error)
	}
}

impl From<LightningError> for MessageHandlingError {
	fn from(error: LightningError) -> Self {
		MessageHandlingError::LightningError(error)
	}
}

/// Manages and reacts to connection events. You probably want to use file descriptors as PeerIds.
/// PeerIds may repeat, but only after socket_disconnected() has been called.
impl<Descriptor: SocketDescriptor, CM: Deref, RM: Deref, L: Deref> PeerManager<Descriptor, CM, RM, L> where
	CM::Target: ChannelMessageHandler,
	RM::Target: RoutingMessageHandler,
	L::Target: Logger {

	/// Constructs a new PeerManager with the given message handlers and node_id secret key
	/// ephemeral_random_data is used to derive per-connection ephemeral keys and must be
	/// cryptographically secure random bytes.
	pub fn new(message_handler: MessageHandler<CM, RM>, our_node_secret: SecretKey, ephemeral_random_data: &[u8; 32], logger: L) -> Self {
		Self {
			inner: PeerManagerImpl::new(message_handler, our_node_secret, ephemeral_random_data, logger)
		}
	}

	/// Get the list of node ids for peers which have completed the initial handshake.
	///
	/// For outbound connections, this will be the same as the their_node_id parameter passed in to
	/// new_outbound_connection, however entries will only appear once the initial handshake has
	/// completed and we are sure the remote peer has the private key for the given node_id.
	pub fn get_peer_node_ids(&self) -> Vec<PublicKey> {
		self.inner.get_peer_node_ids()
	}

	/// Indicates a new outbound connection has been established to a node with the given node_id.
	/// Note that if an Err is returned here you MUST NOT call socket_disconnected for the new
	/// descriptor but must disconnect the connection immediately.
	///
	/// Returns a small number of bytes to send to the remote node (currently always 50).
	///
	/// Panics if descriptor is duplicative with some other descriptor which has not yet had a
	/// socket_disconnected().
	pub fn new_outbound_connection(&self, their_node_id: PublicKey, descriptor: Descriptor) -> Result<Vec<u8>, PeerHandleError> {
		self.inner.new_outbound_connection(their_node_id, descriptor)
	}

	/// Indicates a new inbound connection has been established.
	///
	/// May refuse the connection by returning an Err, but will never write bytes to the remote end
	/// (outbound connector always speaks first). Note that if an Err is returned here you MUST NOT
	/// call socket_disconnected for the new descriptor but must disconnect the connection
	/// immediately.
	///
	/// Panics if descriptor is duplicative with some other descriptor which has not yet had
	/// socket_disconnected called.
	pub fn new_inbound_connection(&self, descriptor: Descriptor) -> Result<(), PeerHandleError> {
		self.inner.new_inbound_connection(descriptor)
	}

	/// Indicates that there is room to write data to the given socket descriptor.
	///
	/// May return an Err to indicate that the connection should be closed.
	///
	/// Will most likely call send_data on the descriptor passed in (or the descriptor handed into
	/// new_*\_connection) before returning. Thus, be very careful with reentrancy issues! The
	/// invariants around calling write_buffer_space_avail in case a write did not fully complete
	/// must still hold - be ready to call write_buffer_space_avail again if a write call generated
	/// here isn't sufficient! Panics if the descriptor was not previously registered in a
	/// new_\*_connection event.
	pub fn write_buffer_space_avail(&self, descriptor: &mut Descriptor) -> Result<(), PeerHandleError> {
		self.inner.write_buffer_space_avail(descriptor)
	}

	/// Indicates that data was read from the given socket descriptor.
	///
	/// May return an Err to indicate that the connection should be closed.
	///
	/// Will *not* call back into send_data on any descriptors to avoid reentrancy complexity.
	/// Thus, however, you almost certainly want to call process_events() after any read_event to
	/// generate send_data calls to handle responses.
	///
	/// If Ok(true) is returned, further read_events should not be triggered until a send_data call
	/// on this file descriptor has resume_read set (preventing DoS issues in the send buffer).
	///
	/// Panics if the descriptor was not previously registered in a new_*_connection event.
	pub fn read_event(&self, peer_descriptor: &mut Descriptor, data: &[u8]) -> Result<bool, PeerHandleError> {
		self.inner.read_event(peer_descriptor, data)
	}

	/// Checks for any events generated by our handlers and processes them. Includes sending most
	/// response messages as well as messages generated by calls to handler functions directly (eg
	/// functions like ChannelManager::process_pending_htlc_forward or send_payment).
	pub fn process_events(&self) {
		self.inner.process_events();
	}

	/// Indicates that the given socket descriptor's connection is now closed.
	///
	/// This must only be called if the socket has been disconnected by the peer or your own
	/// decision to disconnect it and must NOT be called in any case where other parts of this
	/// library (eg PeerHandleError, explicit disconnect_socket calls) instruct you to disconnect
	/// the peer.
	///
	/// Panics if the descriptor was not previously registered in a successful new_*_connection event.
	pub fn socket_disconnected(&self, descriptor: &Descriptor) {
		self.inner.socket_disconnected(descriptor)
	}

	/// This function should be called roughly once every 30 seconds.
	/// It will send pings to each peer and disconnect those which did not respond to the last round of pings.

	/// Will most likely call send_data on all of the registered descriptors, thus, be very careful with reentrancy issues!
	pub fn timer_tick_occured(&self) {
		self.inner.timer_tick_occured()
	}
}


impl<Descriptor: SocketDescriptor, CM: Deref, RM: Deref, L: Deref, TransportImpl: ITransport> PeerManagerImpl<Descriptor, CM, RM, L, TransportImpl> where
		CM::Target: ChannelMessageHandler,
		RM::Target: RoutingMessageHandler,
		L::Target: Logger {

	fn new(message_handler: MessageHandler<CM, RM>, our_node_secret: SecretKey, ephemeral_random_data: &[u8; 32], logger: L) -> Self {
		let mut ephemeral_key_midstate = Sha256::engine();
		ephemeral_key_midstate.input(ephemeral_random_data);

		PeerManagerImpl {
			message_handler,
			peers: Mutex::new(PeerHolder {
				peers: HashMap::new(),
				peers_needing_send: HashSet::new(),
				node_id_to_descriptor: HashMap::new()
			}),
			our_node_secret,
			ephemeral_key_midstate,
			peer_counter_low: AtomicUsize::new(0),
			peer_counter_high: AtomicUsize::new(0),
			logger,
		}
	}

	fn get_peer_node_ids(&self) -> Vec<PublicKey> {
		let peers = self.peers.lock().unwrap();
		peers.peers.values().filter_map(|p| {
			if !p.transport.is_connected() || p.their_features.is_none() {
				return None;
			}
			Some(p.transport.get_their_node_id())
		}).collect()
	}

	fn get_ephemeral_key(&self) -> SecretKey {
		let mut ephemeral_hash = self.ephemeral_key_midstate.clone();
		let low = self.peer_counter_low.fetch_add(1, Ordering::AcqRel);
		let high = if low == 0 {
			self.peer_counter_high.fetch_add(1, Ordering::AcqRel)
		} else {
			self.peer_counter_high.load(Ordering::Acquire)
		};
		ephemeral_hash.input(&byte_utils::le64_to_array(low as u64));
		ephemeral_hash.input(&byte_utils::le64_to_array(high as u64));
		SecretKey::from_slice(&Sha256::from_engine(ephemeral_hash).into_inner()).expect("You broke SHA-256!")
	}

	fn new_outbound_connection(&self, their_node_id: PublicKey, descriptor: Descriptor) -> Result<Vec<u8>, PeerHandleError> {
		let transport = TransportImpl::new_outbound(&self.our_node_secret, &their_node_id, &self.get_ephemeral_key());
		self.new_outbound_connection_with_transport(descriptor, transport)
	}

	fn new_outbound_connection_with_transport(&self, descriptor: Descriptor, mut transport: TransportImpl) -> Result<Vec<u8>, PeerHandleError> {
		let mut peers = self.peers.lock().unwrap();
		let initial_bytes = transport.set_up_outbound();

		if peers.peers.insert(descriptor, Peer::<TransportImpl> {
			transport,
			outbound: true,
			their_features: None,

			pending_outbound_buffer: OutboundQueue::new(MSG_BUFF_SIZE),

			sync_status: InitSyncTracker::NoSyncRequested,

			awaiting_pong: false,
		}).is_some() {
			panic!("PeerManager driver duplicated descriptors!");
		};
		Ok(initial_bytes)
	}

	fn new_inbound_connection(&self, descriptor: Descriptor) -> Result<(), PeerHandleError> {
		let transport = TransportImpl::new_inbound(&self.our_node_secret, &self.get_ephemeral_key());
		self.new_inbound_connection_with_transport(descriptor, transport)
	}

	fn new_inbound_connection_with_transport(&self, descriptor: Descriptor, transport: TransportImpl) -> Result<(), PeerHandleError> {
		let mut peers = self.peers.lock().unwrap();
		if peers.peers.insert(descriptor, Peer::<TransportImpl> {
			transport,
			outbound: false,
			their_features: None,

			pending_outbound_buffer: OutboundQueue::new(MSG_BUFF_SIZE),

			sync_status: InitSyncTracker::NoSyncRequested,

			awaiting_pong: false,
		}).is_some() {
			panic!("PeerManager driver duplicated descriptors!");
		};
		Ok(())
	}

	fn do_attempt_write_data(&self, descriptor: &mut Descriptor, peer: &mut Peer<TransportImpl>) {
		while !peer.pending_outbound_buffer.is_blocked() {
			let queue_space = peer.pending_outbound_buffer.queue_space();
			if queue_space > 0 {
				match peer.sync_status {
					InitSyncTracker::NoSyncRequested => {},
					InitSyncTracker::ChannelsSyncing(c) if c < 0xffff_ffff_ffff_ffff => {
						let steps = ((queue_space + 2) / 3) as u8;
						let all_messages = self.message_handler.route_handler.get_next_channel_announcements(c, steps);
						for &(ref announce, ref update_a_option, ref update_b_option) in all_messages.iter() {
							peer.transport.enqueue_message(announce, &mut peer.pending_outbound_buffer, &*self.logger);
							if let &Some(ref update_a) = update_a_option {
								peer.transport.enqueue_message(update_a, &mut peer.pending_outbound_buffer, &*self.logger);
							}
							if let &Some(ref update_b) = update_b_option {
								peer.transport.enqueue_message(update_b, &mut peer.pending_outbound_buffer, &*self.logger);
							}
							peer.sync_status = InitSyncTracker::ChannelsSyncing(announce.contents.short_channel_id + 1);
						}
						if all_messages.is_empty() || all_messages.len() != steps as usize {
							peer.sync_status = InitSyncTracker::ChannelsSyncing(0xffff_ffff_ffff_ffff);
						}
					},
					InitSyncTracker::ChannelsSyncing(c) if c == 0xffff_ffff_ffff_ffff => {
						let steps = queue_space as u8;
						let all_messages = self.message_handler.route_handler.get_next_node_announcements(None, steps);
						for msg in all_messages.iter() {
							peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
							peer.sync_status = InitSyncTracker::NodesSyncing(msg.contents.node_id);
						}
						if all_messages.is_empty() || all_messages.len() != steps as usize {
							peer.sync_status = InitSyncTracker::NoSyncRequested;
						}
					},
					InitSyncTracker::ChannelsSyncing(_) => unreachable!(),
					InitSyncTracker::NodesSyncing(key) => {
						let steps = queue_space as u8;
						let all_messages = self.message_handler.route_handler.get_next_node_announcements(Some(&key), steps);
						for msg in all_messages.iter() {
							peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
							peer.sync_status = InitSyncTracker::NodesSyncing(msg.contents.node_id);
						}
						if all_messages.is_empty() || all_messages.len() != steps as usize {
							peer.sync_status = InitSyncTracker::NoSyncRequested;
						}
					},
				}
			}

			// No messages to send
			if peer.pending_outbound_buffer.is_empty() {
				break;
			}

			peer.pending_outbound_buffer.try_flush_one(descriptor);
		}
	}

	fn write_buffer_space_avail(&self, descriptor: &mut Descriptor) -> Result<(), PeerHandleError> {
		let mut peers = self.peers.lock().unwrap();
		match peers.peers.get_mut(descriptor) {
			None => panic!("Descriptor for write_event is not already known to PeerManager"),
			Some(peer) => {
				peer.pending_outbound_buffer.unblock();
				self.do_attempt_write_data(descriptor, peer);
			}
		};
		Ok(())
	}

	fn read_event(&self, peer_descriptor: &mut Descriptor, data: &[u8]) -> Result<bool, PeerHandleError> {
		match self.do_read_event(peer_descriptor, data) {
			Ok(res) => Ok(res),
			Err(e) => {
				self.disconnect_event_internal(peer_descriptor, e.no_connection_possible);
				Err(e)
			}
		}
	}

	/// Append a message to a peer's pending outbound/write buffer, and update the map of peers needing sends accordingly.
	fn enqueue_message<M: Encode + Writeable>(&self, peers_needing_send: &mut HashSet<Descriptor>, transport: &mut impl ITransport, output_buffer: &mut impl PayloadQueuer, descriptor: &Descriptor, message: &M) {
		transport.enqueue_message(message, output_buffer, &*self.logger);
		peers_needing_send.insert(descriptor.clone());
	}

	fn do_read_event(&self, peer_descriptor: &mut Descriptor, data: &[u8]) -> Result<bool, PeerHandleError> {
		let pause_read = {
			let mut peers_lock = self.peers.lock().unwrap();
			let peers = &mut *peers_lock;
			let pause_read = match peers.peers.get_mut(peer_descriptor) {
				None => panic!("Descriptor for read_event is not already known to PeerManager"),
				Some(peer) => {

					match peer.transport.process_input(data, &mut peer.pending_outbound_buffer) {
						Err(e) => {
							log_trace!(self.logger, "Error while processing input: {}", e);
							return Err(PeerHandleError { no_connection_possible: false })
						},
						Ok(_) => {

							// If the transport is newly connected, do the appropriate set up for the connection
							if peer.transport.is_connected() {
								let their_node_id = peer.transport.get_their_node_id();

								match peers.node_id_to_descriptor.entry(their_node_id.clone()) {
									hash_map::Entry::Occupied(entry) => {
										if entry.get() != peer_descriptor {
											// Existing entry in map is from a different descriptor, this is a duplicate
											log_trace!(self.logger, "Got second connection with {}, closing", log_pubkey!(&their_node_id));
											return Err(PeerHandleError { no_connection_possible: false });
										} else {
											// read_event for existing peer
										}
									},
									hash_map::Entry::Vacant(entry) => {
										log_trace!(self.logger, "Finished noise handshake for connection with {}", log_pubkey!(&their_node_id));

										if peer.outbound {
											let mut features = InitFeatures::known();
											if !self.message_handler.route_handler.should_request_full_sync(&their_node_id) {
												features.clear_initial_routing_sync();
											}

											let resp = msgs::Init { features };
											self.enqueue_message(&mut peers.peers_needing_send, &mut peer.transport, &mut peer.pending_outbound_buffer, peer_descriptor, &resp);
										}
										entry.insert(peer_descriptor.clone());
									}
								}
							}
						}
					}

					let received_messages = peer.transport.drain_messages(&*self.logger)?;

					for message in received_messages {
						macro_rules! try_potential_handleerror {
							($thing: expr) => {
								match $thing {
									Ok(x) => x,
									Err(e) => {
										match e.action {
											msgs::ErrorAction::DisconnectPeer { msg: _ } => {
												//TODO: Try to push msg
												log_trace!(self.logger, "Got Err handling message, disconnecting peer because {}", e.err);
												return Err(PeerHandleError{ no_connection_possible: false });
											},
											msgs::ErrorAction::IgnoreError => {
												log_trace!(self.logger, "Got Err handling message, ignoring because {}", e.err);
												continue;
											},
											msgs::ErrorAction::SendErrorMessage { msg } => {
												log_trace!(self.logger, "Got Err handling message, sending Error message because {}", e.err);
												self.enqueue_message(&mut peers.peers_needing_send, &mut peer.transport, &mut peer.pending_outbound_buffer, peer_descriptor, &msg);
												continue;
											},
										}
									}
								};
							}
						}

						if let Err(handling_error) = self.handle_message(&mut peers.peers_needing_send, peer, peer_descriptor.clone(), message){
							match handling_error {
								MessageHandlingError::PeerHandleError(e) => { return Err(e) },
								MessageHandlingError::LightningError(e) => {
									try_potential_handleerror!(Err(e));
								},
							}
						}
					}

					self.do_attempt_write_data(peer_descriptor, peer);

					peer.pending_outbound_buffer.queue_space() == 0 // pause_read
				}
			};

			pause_read
		};

		Ok(pause_read)
	}

	/// Process an incoming message and return a decision (ok, lightning error, peer handling error) regarding the next action with the peer
	fn handle_message(&self, peers_needing_send: &mut HashSet<Descriptor>, peer: &mut Peer<TransportImpl>, peer_descriptor: Descriptor, message: wire::Message) -> Result<(), MessageHandlingError> {
		log_trace!(self.logger, "Received message of type {} from {}", message.type_id(), log_pubkey!(peer.transport.get_their_node_id()));

		// Need an Init as first message
		if let wire::Message::Init(_) = message {
		} else if peer.their_features.is_none() {
			log_trace!(self.logger, "Peer {} sent non-Init first message", log_pubkey!(peer.transport.get_their_node_id()));
			return Err(PeerHandleError{ no_connection_possible: false }.into());
		}

		match message {
			// Setup and Control messages:
			wire::Message::Init(msg) => {
				if msg.features.requires_unknown_bits() {
					log_info!(self.logger, "Peer global features required unknown version bits");
					return Err(PeerHandleError{ no_connection_possible: true }.into());
				}
				if msg.features.requires_unknown_bits() {
					log_info!(self.logger, "Peer local features required unknown version bits");
					return Err(PeerHandleError{ no_connection_possible: true }.into());
				}
				if peer.their_features.is_some() {
					return Err(PeerHandleError{ no_connection_possible: false }.into());
				}

				log_info!(
					self.logger, "Received peer Init message: data_loss_protect: {}, initial_routing_sync: {}, upfront_shutdown_script: {}, static_remote_key: {}, unknown flags (local and global): {}",
					if msg.features.supports_data_loss_protect() { "supported" } else { "not supported"},
					if msg.features.initial_routing_sync() { "requested" } else { "not requested" },
					if msg.features.supports_upfront_shutdown_script() { "supported" } else { "not supported"},
					if msg.features.supports_static_remote_key() { "supported" } else { "not supported"},
					if msg.features.supports_unknown_bits() { "present" } else { "none" }
				);

				if msg.features.initial_routing_sync() {
					peer.sync_status = InitSyncTracker::ChannelsSyncing(0);
					peers_needing_send.insert(peer_descriptor.clone());
				}
				if !msg.features.supports_static_remote_key() {
					log_debug!(self.logger, "Peer {} does not support static remote key, disconnecting with no_connection_possible", log_pubkey!(peer.transport.get_their_node_id()));
					return Err(PeerHandleError{ no_connection_possible: true }.into());
				}

				if !peer.outbound {
					let mut features = InitFeatures::known();
					if !self.message_handler.route_handler.should_request_full_sync(&peer.transport.get_their_node_id()) {
						features.clear_initial_routing_sync();
					}

					let resp = msgs::Init { features };
					self.enqueue_message(peers_needing_send, &mut peer.transport, &mut peer.pending_outbound_buffer, &peer_descriptor, &resp);
				}

				self.message_handler.chan_handler.peer_connected(&peer.transport.get_their_node_id(), &msg);
				peer.their_features = Some(msg.features);
			},
			wire::Message::Error(msg) => {
				let mut data_is_printable = true;
				for b in msg.data.bytes() {
					if b < 32 || b > 126 {
						data_is_printable = false;
						break;
					}
				}

				if data_is_printable {
					log_debug!(self.logger, "Got Err message from {}: {}", log_pubkey!(peer.transport.get_their_node_id()), msg.data);
				} else {
					log_debug!(self.logger, "Got Err message from {} with non-ASCII error message", log_pubkey!(peer.transport.get_their_node_id()));
				}
				self.message_handler.chan_handler.handle_error(&peer.transport.get_their_node_id(), &msg);
				if msg.channel_id == [0; 32] {
					return Err(PeerHandleError{ no_connection_possible: true }.into());
				}
			},

			wire::Message::Ping(msg) => {
				if msg.ponglen < 65532 {
					let resp = msgs::Pong { byteslen: msg.ponglen };
					self.enqueue_message(peers_needing_send, &mut peer.transport, &mut peer.pending_outbound_buffer, &peer_descriptor, &resp);
				}
			},
			wire::Message::Pong(_msg) => {
				peer.awaiting_pong = false;
			},

			// Channel messages:
			wire::Message::OpenChannel(msg) => {
				self.message_handler.chan_handler.handle_open_channel(&peer.transport.get_their_node_id(), peer.their_features.clone().unwrap(), &msg);
			},
			wire::Message::AcceptChannel(msg) => {
				self.message_handler.chan_handler.handle_accept_channel(&peer.transport.get_their_node_id(), peer.their_features.clone().unwrap(), &msg);
			},

			wire::Message::FundingCreated(msg) => {
				self.message_handler.chan_handler.handle_funding_created(&peer.transport.get_their_node_id(), &msg);
			},
			wire::Message::FundingSigned(msg) => {
				self.message_handler.chan_handler.handle_funding_signed(&peer.transport.get_their_node_id(), &msg);
			},
			wire::Message::FundingLocked(msg) => {
				self.message_handler.chan_handler.handle_funding_locked(&peer.transport.get_their_node_id(), &msg);
			},

			wire::Message::Shutdown(msg) => {
				self.message_handler.chan_handler.handle_shutdown(&peer.transport.get_their_node_id(), &msg);
			},
			wire::Message::ClosingSigned(msg) => {
				self.message_handler.chan_handler.handle_closing_signed(&peer.transport.get_their_node_id(), &msg);
			},

			// Commitment messages:
			wire::Message::UpdateAddHTLC(msg) => {
				self.message_handler.chan_handler.handle_update_add_htlc(&peer.transport.get_their_node_id(), &msg);
			},
			wire::Message::UpdateFulfillHTLC(msg) => {
				self.message_handler.chan_handler.handle_update_fulfill_htlc(&peer.transport.get_their_node_id(), &msg);
			},
			wire::Message::UpdateFailHTLC(msg) => {
				self.message_handler.chan_handler.handle_update_fail_htlc(&peer.transport.get_their_node_id(), &msg);
			},
			wire::Message::UpdateFailMalformedHTLC(msg) => {
				self.message_handler.chan_handler.handle_update_fail_malformed_htlc(&peer.transport.get_their_node_id(), &msg);
			},

			wire::Message::CommitmentSigned(msg) => {
				self.message_handler.chan_handler.handle_commitment_signed(&peer.transport.get_their_node_id(), &msg);
			},
			wire::Message::RevokeAndACK(msg) => {
				self.message_handler.chan_handler.handle_revoke_and_ack(&peer.transport.get_their_node_id(), &msg);
			},
			wire::Message::UpdateFee(msg) => {
				self.message_handler.chan_handler.handle_update_fee(&peer.transport.get_their_node_id(), &msg);
			},
			wire::Message::ChannelReestablish(msg) => {
				self.message_handler.chan_handler.handle_channel_reestablish(&peer.transport.get_their_node_id(), &msg);
			},

			// Routing messages:
			wire::Message::AnnouncementSignatures(msg) => {
				self.message_handler.chan_handler.handle_announcement_signatures(&peer.transport.get_their_node_id(), &msg);
			},
			wire::Message::ChannelAnnouncement(msg) => {
				let should_forward = match self.message_handler.route_handler.handle_channel_announcement(&msg) {
					Ok(v) => v,
					Err(e) => { return Err(e.into()); },
				};

				if should_forward {
					// TODO: forward msg along to all our other peers!
				}
			},
			wire::Message::NodeAnnouncement(msg) => {
				let should_forward = match self.message_handler.route_handler.handle_node_announcement(&msg) {
					Ok(v) => v,
					Err(e) => { return Err(e.into()); },
				};

				if should_forward {
					// TODO: forward msg along to all our other peers!
				}
			},
			wire::Message::ChannelUpdate(msg) => {
				let should_forward = match self.message_handler.route_handler.handle_channel_update(&msg) {
					Ok(v) => v,
					Err(e) => { return Err(e.into()); },
				};

				if should_forward {
					// TODO: forward msg along to all our other peers!
				}
			},

			// Unknown messages:
			wire::Message::Unknown(msg_type) if msg_type.is_even() => {
				log_debug!(self.logger, "Received unknown even message of type {}, disconnecting peer!", msg_type);
				// Fail the channel if message is an even, unknown type as per BOLT #1.
				return Err(PeerHandleError{ no_connection_possible: true }.into());
			},
			wire::Message::Unknown(msg_type) => {
				log_trace!(self.logger, "Received unknown odd message of type {}, ignoring", msg_type);
			}
		};
		Ok(())
	}

	fn process_events(&self) {
		{
			// TODO: There are some DoS attacks here where you can flood someone's outbound send
			// buffer by doing things like announcing channels on another node. We should be willing to
			// drop optional-ish messages when send buffers get full!

			let mut events_generated = self.message_handler.chan_handler.get_and_clear_pending_msg_events();
			let mut peers_lock = self.peers.lock().unwrap();
			let peers = &mut *peers_lock;
			for event in events_generated.drain(..) {
				macro_rules! get_peer_for_forwarding {
					($node_id: expr, $handle_no_such_peer: block) => {
						{
							let descriptor = match peers.node_id_to_descriptor.get($node_id) {
								Some(descriptor) => descriptor.clone(),
								None => {
									$handle_no_such_peer;
									continue;
								},
							};
							match peers.peers.get_mut(&descriptor) {
								Some(peer) => {
									if peer.their_features.is_none() {
										$handle_no_such_peer;
										continue;
									}
									(descriptor, peer)
								},
								None => panic!("Inconsistent peers set state!"),
							}
						}
					}
				}
				match event {
					MessageSendEvent::SendAcceptChannel { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendAcceptChannel event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.temporary_channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Drop the pending channel? (or just let it timeout, but that sucks)
							});
						if peer.transport.is_connected() {
							peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
						}
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendOpenChannel { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendOpenChannel event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.temporary_channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Drop the pending channel? (or just let it timeout, but that sucks)
							});
						if peer.transport.is_connected() {
							peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
						}
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendFundingCreated { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendFundingCreated event in peer_handler for node {} for channel {} (which becomes {})",
								log_pubkey!(node_id),
								log_bytes!(msg.temporary_channel_id),
								log_funding_channel_id!(msg.funding_txid, msg.funding_output_index));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: generate a DiscardFunding event indicating to the wallet that
								//they should just throw away this funding transaction
							});
						if peer.transport.is_connected() {
							peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
						}
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendFundingSigned { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendFundingSigned event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: generate a DiscardFunding event indicating to the wallet that
								//they should just throw away this funding transaction
							});
						if peer.transport.is_connected() {
							peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
						}
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendFundingLocked { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendFundingLocked event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						if peer.transport.is_connected() {
							peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
						}
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendAnnouncementSignatures event in peer_handler for node {} for channel {})",
								log_pubkey!(node_id),
								log_bytes!(msg.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: generate a DiscardFunding event indicating to the wallet that
								//they should just throw away this funding transaction
							});
						if peer.transport.is_connected() {
							peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
						}
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
						log_trace!(self.logger, "Handling UpdateHTLCs event in peer_handler for node {} with {} adds, {} fulfills, {} fails for channel {}",
								log_pubkey!(node_id),
								update_add_htlcs.len(),
								update_fulfill_htlcs.len(),
								update_fail_htlcs.len(),
								log_bytes!(commitment_signed.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						if peer.transport.is_connected() {
							for msg in update_add_htlcs {
								peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
							}
							for msg in update_fulfill_htlcs {
								peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
							}
							for msg in update_fail_htlcs {
								peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
							}
							for msg in update_fail_malformed_htlcs {
								peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
							}
							if let &Some(ref msg) = update_fee {
								peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
							}
							peer.transport.enqueue_message(commitment_signed, &mut peer.pending_outbound_buffer, &*self.logger);
						}
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendRevokeAndACK event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						if peer.transport.is_connected() {
							peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
						}
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendClosingSigned { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendClosingSigned event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						if peer.transport.is_connected() {
							peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
						}
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendShutdown { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling Shutdown event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						if peer.transport.is_connected() {
							peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
						}
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendChannelReestablish { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendChannelReestablish event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						if peer.transport.is_connected() {
							peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
						}
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
						log_trace!(self.logger, "Handling BroadcastChannelAnnouncement event in peer_handler for short channel id {}", msg.contents.short_channel_id);
						if self.message_handler.route_handler.handle_channel_announcement(msg).is_ok() && self.message_handler.route_handler.handle_channel_update(update_msg).is_ok() {
							for (ref descriptor, ref mut peer) in peers.peers.iter_mut() {
								if !peer.transport.is_connected() || peer.their_features.is_none() ||
									!peer.should_forward_channel_announcement(msg.contents.short_channel_id) {
									continue
								}

								let their_node_id = peer.transport.get_their_node_id();
								if their_node_id == msg.contents.node_id_1 || their_node_id == msg.contents.node_id_2 {
									continue
								}
								if peer.transport.is_connected() {
									peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
									peer.transport.enqueue_message(update_msg, &mut peer.pending_outbound_buffer, &*self.logger);
								}
								self.do_attempt_write_data(&mut (*descriptor).clone(), peer);
							}
						}
					},
					MessageSendEvent::BroadcastNodeAnnouncement { ref msg } => {
						log_trace!(self.logger, "Handling BroadcastNodeAnnouncement event in peer_handler");
						if self.message_handler.route_handler.handle_node_announcement(msg).is_ok() {
							for (ref descriptor, ref mut peer) in peers.peers.iter_mut() {
								if !peer.transport.is_connected() || peer.their_features.is_none() ||
										!peer.should_forward_node_announcement(msg.contents.node_id) {
									continue
								}
								if peer.transport.is_connected() {
									peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
								}
								self.do_attempt_write_data(&mut (*descriptor).clone(), peer);
							}
						}
					},
					MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
						log_trace!(self.logger, "Handling BroadcastChannelUpdate event in peer_handler for short channel id {}", msg.contents.short_channel_id);
						if self.message_handler.route_handler.handle_channel_update(msg).is_ok() {
							for (ref descriptor, ref mut peer) in peers.peers.iter_mut() {
								if !peer.transport.is_connected() || peer.their_features.is_none() ||
									!peer.should_forward_channel_announcement(msg.contents.short_channel_id)  {
									continue
								}
								if peer.transport.is_connected() {
									peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
								}
								self.do_attempt_write_data(&mut (*descriptor).clone(), peer);
							}
						}
					},
					MessageSendEvent::PaymentFailureNetworkUpdate { ref update } => {
						self.message_handler.route_handler.handle_htlc_fail_channel_update(update);
					},
					MessageSendEvent::HandleError { ref node_id, ref action } => {
						match *action {
							msgs::ErrorAction::DisconnectPeer { ref msg } => {
								if let Some(mut descriptor) = peers.node_id_to_descriptor.remove(node_id) {
									peers.peers_needing_send.remove(&descriptor);
									if let Some(mut peer) = peers.peers.remove(&descriptor) {
										if let Some(ref msg) = *msg {
											log_trace!(self.logger, "Handling DisconnectPeer HandleError event in peer_handler for node {} with message {}",
													log_pubkey!(node_id),
													msg.data);
											if peer.transport.is_connected() {
												peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
											}
											// This isn't guaranteed to work, but if there is enough free
											// room in the send buffer, put the error message there...
											self.do_attempt_write_data(&mut descriptor, &mut peer);
										} else {
											log_trace!(self.logger, "Handling DisconnectPeer HandleError event in peer_handler for node {} with no message", log_pubkey!(node_id));
										}
									}
									descriptor.disconnect_socket();
									self.message_handler.chan_handler.peer_disconnected(&node_id, false);
								}
							},
							msgs::ErrorAction::IgnoreError => {},
							msgs::ErrorAction::SendErrorMessage { ref msg } => {
								log_trace!(self.logger, "Handling SendErrorMessage HandleError event in peer_handler for node {} with message {}",
										log_pubkey!(node_id),
										msg.data);
								let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
									//TODO: Do whatever we're gonna do for handling dropped messages
								});
								if peer.transport.is_connected() {
									peer.transport.enqueue_message(msg, &mut peer.pending_outbound_buffer, &*self.logger);
								}
								self.do_attempt_write_data(&mut descriptor, peer);
							},
						}
					}
				}
			}

			for mut descriptor in peers.peers_needing_send.drain() {
				match peers.peers.get_mut(&descriptor) {
					Some(peer) => self.do_attempt_write_data(&mut descriptor, peer),
					None => panic!("Inconsistent peers set state!"),
				}
			}
		}
	}

	fn socket_disconnected(&self, descriptor: &Descriptor) {
		self.disconnect_event_internal(descriptor, false);
	}

	fn disconnect_event_internal(&self, descriptor: &Descriptor, no_connection_possible: bool) {
		let mut peers = self.peers.lock().unwrap();
		peers.peers_needing_send.remove(descriptor);
		let peer_option = peers.peers.remove(descriptor);
		match peer_option {
			None => panic!("Descriptor for disconnect_event is not already known to PeerManager"),
			Some(peer) => {
				if peer.transport.is_connected() {
					let node_id = peer.transport.get_their_node_id();

					if peers.node_id_to_descriptor.get(&node_id).unwrap() == descriptor {
						peers.node_id_to_descriptor.remove(&node_id);
						self.message_handler.chan_handler.peer_disconnected(&node_id, no_connection_possible);
					} else {
						// This must have been generated from a duplicate connection error
					}
				} else {
					// Unconnected nodes never make it into node_id_to_descriptor
				}
			}
		};
	}

	fn timer_tick_occured(&self) {
		let mut peers_lock = self.peers.lock().unwrap();
		{
			let peers = &mut *peers_lock;
			let peers_needing_send = &mut peers.peers_needing_send;
			let node_id_to_descriptor = &mut peers.node_id_to_descriptor;
			let peers = &mut peers.peers;
			let mut descriptors_needing_disconnect = Vec::new();

			peers.retain(|descriptor, peer| {
				if peer.awaiting_pong {
					peers_needing_send.remove(descriptor);
					descriptors_needing_disconnect.push(descriptor.clone());
					let their_node_id = peer.transport.get_their_node_id();
					log_trace!(self.logger, "Disconnecting peer with id {} due to ping timeout", their_node_id);
					node_id_to_descriptor.remove(&their_node_id);
					self.message_handler.chan_handler.peer_disconnected(&their_node_id, false);

					return false;
				}

				let mut needs_to_write_data = false;
				if peer.transport.is_connected() {
					let ping = msgs::Ping {
						ponglen: 0,
						byteslen: 64,
					};
					peer.transport.enqueue_message(&ping, &mut peer.pending_outbound_buffer, &*self.logger);
					needs_to_write_data = true;
				}

				if needs_to_write_data {
					let mut descriptor_clone = descriptor.clone();
					self.do_attempt_write_data(&mut descriptor_clone, peer);
				}

				peer.awaiting_pong = true;
				true
			});

			for mut descriptor in descriptors_needing_disconnect.drain(..) {
				descriptor.disconnect_socket();
			}
		}
	}
}

// Unit tests of the PeerManager object. This leverage dependency inversion by passing in a Transport
// test double and configuring it in various ways to create the conditions needed to exercise the
// interesting code paths. This allows isolated testing of the PeerManager without worrying about
// handshakes or encryption. The TransportTestStub abstracts that and provides a behavior where
// enqueue_message() places Messages on the outbound queue unencrypted for easy validation through
// the SocketDescriptor.
//
// In addition, it makes use of the Spy pattern for the MessageHandler and RouteHandler traits to
// ensure that the correct callbacks are called given the correct inputs.
#[cfg(test)]
mod unit_tests {
	use super::*;
	use ln::peers::test_util::*;

	use bitcoin::secp256k1::{Secp256k1, Signature};
	use ln::channelmanager::{PaymentHash, PaymentPreimage};
	use ln::features::{ChannelFeatures, NodeFeatures};
	use ln::msgs::*;
	use util::events::MessageSendEvent::*;
	use util::test_utils::{RoutingMessageHandlerTestStub, TestLogger, ChannelMessageHandlerTestSpy, TestChannelMessageHandler, RoutingMessageHandlerTestSpy, TestRoutingMessageHandler};
	use std::cell::RefCell;

	// Split out in a macro so tests can use this value to create test state before the TestCtx is
	// created
	macro_rules! test_ctx_their_node_id {
		() => {{
			let their_node_secret = SecretKey::from_slice(&[0x_12_u8; 32]).unwrap();
			PublicKey::from_secret_key(&Secp256k1::new(), &their_node_secret)
		}}
	}

	struct TestCtx<CM: ChannelMessageHandler=ChannelMessageHandlerTestSpy, RM: RoutingMessageHandler=RoutingMessageHandlerTestStub> {
		chan_handler: CM,
		logger: TestLogger,
		random_data: [u8; 32],
		route_handler: RM,
		their_node_id: PublicKey,
	}

	impl<CM: ChannelMessageHandler, RM: RoutingMessageHandler> TestCtx<CM, RM> {

		fn new() -> TestCtx<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub> {
			TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::with_channel_and_routing(ChannelMessageHandlerTestSpy::new(), RoutingMessageHandlerTestStub::new())
		}

		fn with_channel_and_routing(chan_handler: CM, route_handler: RM) -> Self {

			Self {
				chan_handler,
				logger: TestLogger::new(),
				random_data: [0; 32],
				route_handler,
				their_node_id: test_ctx_their_node_id!()
			}
		}

		fn with_routing_handler(route_handler: RM) -> TestCtx<ChannelMessageHandlerTestSpy, RM> {
			TestCtx::<ChannelMessageHandlerTestSpy, RM>::with_channel_and_routing(ChannelMessageHandlerTestSpy::new(), route_handler)
		}

		fn with_channel_handler(channel_handler: CM) -> TestCtx<CM, RoutingMessageHandlerTestStub> {
			TestCtx::<CM, RoutingMessageHandlerTestStub>::with_channel_and_routing(channel_handler, RoutingMessageHandlerTestStub::new())
		}
	}

	macro_rules! new_unconnected_transport {
		() => {{
			RefCell::new(TransportStubBuilder::new().finish())
		}}
	}

	macro_rules! new_connected_transport {
		($test_ctx:expr) => {{
			RefCell::new(TransportStubBuilder::new().set_connected(&$test_ctx.their_node_id).finish())
		}}
	}

	macro_rules! new_peer_manager_for_test {
		($test_ctx:expr) => {{
			let our_node_secret = SecretKey::from_slice(&[0x_11_u8; 32]).unwrap();
			let message_handler = MessageHandler {
				chan_handler: &$test_ctx.chan_handler,
				route_handler:  &$test_ctx.route_handler,
			};
			PeerManagerImpl::<_, _, _, _, &RefCell<TransportStub>>::new(message_handler, our_node_secret, &$test_ctx.random_data, &$test_ctx.logger)
		}}
	}

	// Generates a PeerManager & TransportStub for test that has already connected and parsed
	// the Init message. To reduce test expansion, this only tests with an outbound connection with
	// the understanding that after the init process, both connections are identical.
	macro_rules! new_peer_manager_post_init {
		($test_ctx: expr, $descriptor: expr, $transport: expr) => {{
			let mut features = InitFeatures::known();
			features.clear_initial_routing_sync();

			$transport.borrow_mut().add_incoming_message(Message::Init(Init { features }));

			let peer_manager = new_peer_manager_for_test!(&$test_ctx);
			new_outbound!(peer_manager, $descriptor, $transport);
			assert_matches!(peer_manager.read_event($descriptor, &[]), Ok(false));

			// Drain pre-init data from descriptor in recording
			$descriptor.clear_recording();

			peer_manager
		}}
	}

	macro_rules! new_outbound {
		($peer_manager: expr, $descriptor: expr, $transport: expr) => {{
			$peer_manager.new_outbound_connection_with_transport($descriptor.clone(), $transport).unwrap()
		}}
	}

	macro_rules! new_inbound {
		($peer_manager: expr, $descriptor: expr, $transport: expr) => {{
			$peer_manager.new_inbound_connection_with_transport($descriptor.clone(), $transport).unwrap()
		}}
	}

	// Assert read_event() returns an error with the proper no_connection_possible set
	macro_rules! assert_read_event_errors {
		($peer_manager: expr, $descriptor: expr, $no_connection_possible: expr) => {{
			assert_matches!($peer_manager.read_event($descriptor, &[]), Err(PeerHandleError { no_connection_possible: $no_connection_possible }))
		}}
	}

	// Assert that a given slice matches a wire::Message pattern
	macro_rules! assert_matches_message {
		($bytes: expr, $message_pattern: pat) => {{
			let mut reader = ::std::io::Cursor::new($bytes);
			let message_result = wire::read(&mut reader);
			let message = message_result.unwrap();
			assert_matches!(message, $message_pattern)
		}}
	}

	// Convenience macro for returning the spy value by function name
	macro_rules! channel_handler_called {
		($test_ctx:expr, $fn_name: ident) => {{
			$test_ctx.chan_handler.called.lock().unwrap().$fn_name
		}}
	}

	// Convenience macro for returning the spy value by function name
	macro_rules! route_handler_called {
		($test_ctx:expr, $fn_name: ident) => {{
			$test_ctx.route_handler.called.lock().unwrap().$fn_name
		}}
	}

	//   ____                _   _____                 _     _____         _   _
	// 	|  _ \ ___  __ _  __| | | ____|_   _____ _ __ | |_  |_   _|__  ___| |_(_)_ __   __ _
	// 	| |_) / _ \/ _` |/ _` | |  _| \ \ / / _ \ '_ \| __|   | |/ _ \/ __| __| | '_ \ / _` |
	//  |  _ <  __/ (_| | (_| | | |___ \ V /  __/ | | | |_    | |  __/\__ \ |_| | | | | (_| |
	// 	|_| \_\___|\__,_|\__,_| |_____| \_/ \___|_| |_|\__|   |_|\___||___/\__|_|_| |_|\__, |
	// 	                                                                                |___/

	// Test that a new inbound connection:
	// * does not show up in get_peer_node_ids()
	#[test]
	fn new_inbound_not_in_get_peer_node_ids() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let descriptor = SocketDescriptorMock::new();
		let mut transport = new_unconnected_transport!();
		let peer_manager = new_peer_manager_for_test!(&test_ctx);

		new_inbound!(peer_manager, descriptor, &mut transport);

		assert!(peer_manager.get_peer_node_ids().is_empty());
		descriptor.assert_called_with(vec![]);
	}

	// Test that a new outbound connection:
	// * does not show up in get_peer_node_ids()
	#[test]
	fn new_outbound_not_in_get_peer_node_ids() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let descriptor = SocketDescriptorMock::new();
		let mut transport = new_unconnected_transport!();
		let peer_manager = new_peer_manager_for_test!(&test_ctx);

		new_outbound!(peer_manager, descriptor, &mut transport);

		assert!(peer_manager.get_peer_node_ids().is_empty());
		descriptor.assert_called_with(vec![]);
	}

	// Test that a new inbound connection:
	// * returns errors from the Transport code
	#[test]
	fn new_inbound_transport_error_returns_error() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let mut transport = RefCell::new(TransportStubBuilder::new().process_returns_error().finish());
		let peer_manager = new_peer_manager_for_test!(&test_ctx);

		new_inbound!(peer_manager, descriptor, &mut transport);

		assert_read_event_errors!(peer_manager, &mut descriptor, false);
	}

	// Test that a new outbound connection:
	// * returns errors from the Transport code
	#[test]
	fn new_outbound_transport_error_returns_error() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let mut transport = RefCell::new(TransportStubBuilder::new().process_returns_error().finish());
		let peer_manager = new_peer_manager_for_test!(&test_ctx);

		new_outbound!(peer_manager, descriptor, &mut transport);

		assert_read_event_errors!(peer_manager, &mut descriptor, false);
	}

	// Test that an inbound connection with a connected Transport, but no Init message
	// * does not show up in get_peer_node_ids()
	// * does not send an Init message in process_events() (must receive from Initiator first)
	#[test]
	fn inbound_connected_transport_not_in_get_peer_node_ids() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let mut transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);

		new_inbound!(peer_manager, descriptor, &mut transport);
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));

		assert!(peer_manager.get_peer_node_ids().is_empty());
		peer_manager.process_events();
		descriptor.assert_called_with(vec![]);
	}

	// Test that an outbound connection with a connected Transport, but no Init message
	// * does not call peer_disconnected callback if an error is returned from Transport
	// XXXBUG: peer_connected is called after the Init message, but peer_disconnected is called
	//         with any error after the NOISE handshake is complete
	#[test]
	fn outbound_connected_transport_error_does_not_call_peer_disconnected_on_error() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		new_outbound!(peer_manager, descriptor, &transport);
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));

		// Signal the error in transport and ensure we don't send a dangling peer_disconnected
		transport.borrow_mut().process_returns_error();
		assert_read_event_errors!(peer_manager, &mut descriptor, false);
		assert!(!channel_handler_called!(&test_ctx, peer_connected));
		// assert!(!channel_handler_called!(&test_ctx, peer_disconnected));
	}

	// Test that an inbound connection with a connected Transport and queued Init message:
	// * XXXBUG: does not send anything in read_event()
	// * responds with an Init message in process_events()
	// * calls the peer_connected channel manager callback
	#[test]
	fn inbound_connected_transport_responds_with_init() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let mut transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		transport.borrow_mut().add_incoming_message(Message::Init(Init { features: InitFeatures::known() }));

		new_inbound!(peer_manager, descriptor, &mut transport);

		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
		// descriptor.assert_called_with(vec![]);

		peer_manager.process_events();

		let recording = descriptor.get_recording();
		assert_matches_message!(&recording[0].0, Message::Init(_));
		assert!(channel_handler_called!(&test_ctx, peer_connected));
	}

	// Test that an inbound connection with a connected Transport and queued Init message:
	// * read_event() returns true if the outbound queue is full
	// * read_event() returns false once room is made and write_buffer_space_avail is called
	// Test leverages a 0 capacity SocketDescriptor and the initial routing sync from TestRoutingMessagehandler
	// to fill the queue
	#[test]
	fn inbound_connected_transport_full_outbound_queue() {
		let routing_handler = TestRoutingMessageHandler::new();
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, TestRoutingMessageHandler>::with_routing_handler(routing_handler);
		let mut descriptor = SocketDescriptorMock::with_fixed_size(0);
		let mut transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		transport.borrow_mut().add_incoming_message(Message::Init(Init { features: InitFeatures::known() }));

		new_inbound!(peer_manager, descriptor, &mut transport);

		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(true));

		// Call w/o write_buffer_space_avail still returns Ok(true)
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(true));

		// Call w/o more room in SocketDescriptor still returns Ok(true)
		peer_manager.write_buffer_space_avail(&mut descriptor).unwrap();
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(true));

		// Call after more room in SocketDescriptor returns Ok(false)
		descriptor.make_room(100000);
		peer_manager.write_buffer_space_avail(&mut descriptor).unwrap();
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));

		peer_manager.process_events();

		let recording = descriptor.get_recording();
		assert_matches_message!(&recording[0].0, Message::Init(_));
		assert!(channel_handler_called!(&test_ctx, peer_connected));
	}

	// Test that an outbound connection with a connected Transport
	// * does not show up in get_peer_node_ids()
	// * XXXBUG: does not send anything in read_event()
	// * sends an Init message in process_events()
	#[test]
	fn outbound_connected_transport_sends_init_in_process_events() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let mut transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);

		new_outbound!(peer_manager, descriptor, &mut transport);
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
		// XXXBUG: Should not call back into descriptor
		// descriptor.assert_called_with(vec![]);

		assert!(peer_manager.get_peer_node_ids().is_empty());

		peer_manager.process_events();
		let recording = descriptor.get_recording();
		assert_eq!(1, recording.len());

		assert_matches_message!(&recording[0].0, Message::Init(_));
	}

	// Test that an outbound connection with a connected Transport
	// * errors when receiving a Non-Init message first
	// * calls the peer_disconnected channel manager callback
	#[test]
	fn inbound_connected_transport_non_init_first_fails() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let mut transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		transport.borrow_mut().add_incoming_message(Message::Ping(Ping { ponglen: 0, byteslen: 0 }));

		new_inbound!(peer_manager, descriptor, &mut transport);
		assert_read_event_errors!(peer_manager, &mut descriptor, false);
		assert!(channel_handler_called!(&test_ctx, peer_disconnected));
	}

	// Test that an outbound connection with a connected Transport
	// * errors when receiving a Non-Init message first
	// * calls the peer_disconnected channel manager callback
	#[test]
	fn outbound_connected_transport_non_init_first_fails() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let mut transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		transport.borrow_mut().add_incoming_message(Message::Ping(Ping { ponglen: 0, byteslen: 0 }));

		new_outbound!(peer_manager, descriptor, &mut transport);
		assert_read_event_errors!(peer_manager, &mut descriptor, false);
		assert!(channel_handler_called!(&test_ctx, peer_disconnected));
	}

	// Test that an inbound connection with a connected Transport
	// * errors out with no_connection_possible if an Init message contains requires_unknown_bits
	// * calls the peer_disconnected channel manager callback
	#[test]
	fn inbound_connected_transport_init_with_required_unknown_first_fails() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let mut transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		let mut features = InitFeatures::known();
		features.set_required_unknown_bits();
		transport.borrow_mut().add_incoming_message(Message::Init(Init { features }));

		new_inbound!(peer_manager, descriptor, &mut transport);
		assert_read_event_errors!(peer_manager, &mut descriptor, true);
		assert!(channel_handler_called!(&test_ctx, peer_disconnected));
	}

	// Test that an outbound connection with a connected Transport
	// * errors out with no_connection_possible if an Init message contains requires_unknown_bits
	// * calls the peer_disconnected channel manager callback
	#[test]
	fn outbound_connected_transport_init_with_required_unknown_first_fails() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let mut transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		let mut features = InitFeatures::known();
		features.set_required_unknown_bits();
		transport.borrow_mut().add_incoming_message(Message::Init(Init { features }));

		new_outbound!(peer_manager, descriptor, &mut transport);
		assert_read_event_errors!(peer_manager, &mut descriptor, true);
		assert!(channel_handler_called!(&test_ctx, peer_disconnected));
	}

	// Test that an inbound connection with a connected Transport
	// * errors out with no_connection_possible if an Init message does not contain requires_static_remote_key
	// * calls the peer_disconnected channel manager callback
	#[test]
	fn inbound_connected_transport_init_with_clear_requires_static_remote_key() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let mut transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		let mut features = InitFeatures::known();
		features.clear_requires_static_remote_key();
		transport.borrow_mut().add_incoming_message(Message::Init(Init { features }));

		new_inbound!(peer_manager, descriptor, &mut transport);
		assert_read_event_errors!(peer_manager, &mut descriptor, true);
		assert!(channel_handler_called!(&test_ctx, peer_disconnected));
	}

	// Test that an outbound connection with a connected Transport
	// * errors out with no_connection_possible if an Init message does not contain requires_static_remote_key
	// * calls the peer_disconnected channel manager callback
	#[test]
	fn outbound_connected_transport_init_with_clear_requires_static_remote_key() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let mut transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		let mut features = InitFeatures::known();
		features.clear_requires_static_remote_key();
		transport.borrow_mut().add_incoming_message(Message::Init(Init { features }));

		new_outbound!(peer_manager, descriptor, &mut transport);
		assert_read_event_errors!(peer_manager, &mut descriptor, true);
		assert!(channel_handler_called!(&test_ctx, peer_disconnected));
	}

	// Test that an inbound connection with a connected Transport and queued Init Message:
	// * shows up in get_peer_node_ids()
	// * calls the peer_connected channel manager callback
	#[test]
	fn inbound_connected_transport_after_init_in_get_peer_node_ids() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let mut transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		transport.borrow_mut().add_incoming_message(Message::Init(Init { features: InitFeatures::known() }));

		new_inbound!(peer_manager, descriptor, &mut transport);

		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));

		assert!(peer_manager.get_peer_node_ids().contains(&test_ctx.their_node_id));
		assert!(channel_handler_called!(&test_ctx, peer_connected));
	}

	// Test that an outbound connection with a connected Transport and queued Init Message:
	// * shows up in get_peer_node_ids()
	// * calls the peer_connected channel manager callback
	#[test]
	fn outbound_connected_transport_after_init_in_get_peer_node_ids() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let mut transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		transport.borrow_mut().add_incoming_message(Message::Init(Init { features: InitFeatures::known() }));

		new_outbound!(peer_manager, descriptor, &mut transport);

		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));

		assert!(peer_manager.get_peer_node_ids().contains(&test_ctx.their_node_id));
		assert!(channel_handler_called!(&test_ctx, peer_connected));
	}

	// Test that a post-Init connection:
	// * is removed from get_peer_node_ids() on an error coming out of Transport
	// * calls the peer_disconnected channel manager callback
	#[test]
	fn post_init_connected_after_error_not_in_get_peer_node_ids() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		// Set transport to return an error
		transport.borrow_mut().process_returns_error();

		// Verify errors out and removed from get_peer_node_ids()
		assert_read_event_errors!(peer_manager, &mut descriptor, false);
		assert!(peer_manager.get_peer_node_ids().is_empty());
		assert!(channel_handler_called!(&test_ctx, peer_disconnected));
	}

	// Test that a post-Init duplicate connection:
	// * is errored during read_event()
	// * and the original connection is still in get_peer_node_ids()
	#[test]
	fn post_init_duplicate_connection_errors_and_original_keeps_existing() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		// Create a duplicate connection from the same node_id
		let mut duplicate_connection_descriptor = SocketDescriptorMock::new();
		let mut duplicate_connection_transport = RefCell::new(TransportStubBuilder::new()
			.set_connected(&test_ctx.their_node_id)
			.finish());
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		assert!(peer_manager.get_peer_node_ids().contains(&test_ctx.their_node_id));

		// Duplicate connection errors out
		new_outbound!(peer_manager, duplicate_connection_descriptor, &mut duplicate_connection_transport);
		assert_read_event_errors!(peer_manager, &mut duplicate_connection_descriptor, false);

		// And any queued messages such as an outgoing Init are never sent
		peer_manager.process_events();
		duplicate_connection_descriptor.assert_called_with(vec![]);

		// But the original still exists in get_peer_node_ids()
		assert!(peer_manager.get_peer_node_ids().contains(&test_ctx.their_node_id));
	}

	//   __  __                                  _____         _   _
	// 	|  \/  | ___  ___ ___  __ _  __ _  ___  |_   _|__  ___| |_(_)_ __   __ _
	// 	| |\/| |/ _ \/ __/ __|/ _` |/ _` |/ _ \   | |/ _ \/ __| __| | '_ \ / _` |
	//  | |  | |  __/\__ \__ \ (_| | (_| |  __/   | |  __/\__ \ |_| | | | | (_| |
	// 	|_|  |_|\___||___/___/\__,_|\__, |\___|   |_|\___||___/\__|_|_| |_|\__, |
	// 	                             |___/                                  |___/

	// Test that a post-Init connection:
	// * returns an error if it receives a second Init message
	// * calls the peer_disconnected channel manager callback
	#[test]
	fn post_init_second_init_fails() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		transport.borrow_mut().add_incoming_message(Message::Init(Init { features: InitFeatures::known() }));

		assert_read_event_errors!(peer_manager, &mut descriptor, false);
		assert!(channel_handler_called!(&test_ctx, peer_disconnected));
	}

	// Test that a post-Init connection:
	// * does not propagate an Error Message with no printable
	// * calls the handle_error channel manager callback
	#[test]
	fn post_init_error_message_without_printable() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		transport.borrow_mut().add_incoming_message(Message::Error(ErrorMessage { channel_id: [1; 32], data: "".to_string() }));

		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
		assert!(channel_handler_called!(&test_ctx, handle_error));
	}

	// Test that a post-Init connection:
	// * does not propagate an Error Message with printable
	// * calls the handle_error channel manager callback
	#[test]
	fn post_init_error_message_with_printable() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		transport.borrow_mut().add_incoming_message(Message::Error(ErrorMessage { channel_id: [1; 32], data: "error".to_string() }));

		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
		assert!(channel_handler_called!(&test_ctx, handle_error));
	}

	// Test that a post-Init connection:
	// * does not propagate an Error Message with a control character
	// * calls the handle_error channel manager callback
	#[test]
	fn post_init_error_message_with_non_ascii_ignored() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		transport.borrow_mut().add_incoming_message(Message::Error(ErrorMessage { channel_id: [1; 32], data: "\x00".to_string() }));

		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
		assert!(channel_handler_called!(&test_ctx, handle_error));
	}

	// Test that a post-Init connection:
	// * Returns an error when it receives an Error Message with a 0 channel_id
	// * calls the handle_error channel manager callback
	#[test]
	fn post_init_error_message_with_zero_channel_id() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		transport.borrow_mut().add_incoming_message(Message::Error(ErrorMessage { channel_id: [0; 32], data: "".to_string() }));

		assert_read_event_errors!(peer_manager, &mut descriptor, true);
		assert!(channel_handler_called!(&test_ctx, handle_error));
	}

	// Test that a post-Init connection:
	// * Returns an error when it receives Message::Unknown (even)
	#[test]
	fn post_init_unknown_message_even() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		transport.borrow_mut().add_incoming_message(Message::Unknown(wire::MessageType(254)));

		assert_read_event_errors!(peer_manager, &mut descriptor, true);
	}

	// Test that a post-Init connection:
	// * Ignores a Message::Unknown (odd)
	#[test]
	fn post_init_unknown_message_odd() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		transport.borrow_mut().add_incoming_message(Message::Unknown(wire::MessageType(255)));

		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
	}

	// Intentionally different from TestCtx::their_node_id do test known and unknown ids
	macro_rules! fake_public_key {
		() => {{
			let their_node_secret = SecretKey::from_slice(&[0x_11_u8; 32]).unwrap();
			PublicKey::from_secret_key(&Secp256k1::new(), &their_node_secret)
		}}
	}

	macro_rules! fake_valid_sig {
		() => {{
			Signature::from_der(hex::decode("3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45").unwrap().as_slice()).unwrap()
		}}
	}

	// Test that a post-init connection:
	// * calls the correct ChannelMessageHandler callback given the correct message type
	macro_rules! generate_handle_message_test {
		($expected_cb: ident, $msg: expr) => {
			#[test]
			fn $expected_cb() {
				let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
				let mut descriptor = SocketDescriptorMock::new();
				let transport = new_connected_transport!(&test_ctx);
				let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);
				transport.borrow_mut().add_incoming_message($msg);

				assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
				assert!(channel_handler_called!(&test_ctx, $expected_cb));
			}
		}
	}

	macro_rules! open_channel_msg {
		() => {{
			OpenChannel {
				chain_hash: Default::default(),
				temporary_channel_id: [0; 32],
				funding_satoshis: 0,
				push_msat: 0,
				dust_limit_satoshis: 0,
				max_htlc_value_in_flight_msat: 0,
				channel_reserve_satoshis: 0,
				htlc_minimum_msat: 0,
				feerate_per_kw: 0,
				to_self_delay: 0,
				max_accepted_htlcs: 0,
				funding_pubkey: fake_public_key!(),
				revocation_basepoint: fake_public_key!(),
				delayed_payment_basepoint: fake_public_key!(),
				htlc_basepoint: fake_public_key!(),
				payment_point: fake_public_key!(),
				first_per_commitment_point: fake_public_key!(),
				channel_flags: 0,
				shutdown_scriptpubkey: OptionalField::Absent
			}
		}}
	}

	generate_handle_message_test!(handle_open_channel, Message::OpenChannel(open_channel_msg!()));

	macro_rules! accept_channel_msg {
		() => {{
			AcceptChannel {
				temporary_channel_id: [0; 32],
				dust_limit_satoshis: 0,
				max_htlc_value_in_flight_msat: 0,
				channel_reserve_satoshis: 0,
				htlc_minimum_msat: 0,
				minimum_depth: 0,
				to_self_delay: 0,
				max_accepted_htlcs: 0,
				funding_pubkey: fake_public_key!(),
				revocation_basepoint: fake_public_key!(),
				payment_point: fake_public_key!(),
				delayed_payment_basepoint: fake_public_key!(),
				htlc_basepoint: fake_public_key!(),
				first_per_commitment_point: fake_public_key!(),
				shutdown_scriptpubkey: OptionalField::Absent
			}
		}}
	}
	generate_handle_message_test!(handle_accept_channel, {
		Message::AcceptChannel(accept_channel_msg!())
	});

	macro_rules! funding_created_msg {
		() => {{
			FundingCreated {
				temporary_channel_id: [0; 32],
				funding_txid: Default::default(),
				funding_output_index: 0,
				signature: fake_valid_sig!()
			}
		}}
	}

	generate_handle_message_test!(handle_funding_created, {
		Message::FundingCreated(funding_created_msg!())
	});

	macro_rules! funding_signed_msg {
		() => {{
			FundingSigned {
				channel_id: [0; 32],
				signature: fake_valid_sig!()
			}
		}}
	}

	generate_handle_message_test!(handle_funding_signed, {
		Message::FundingSigned(funding_signed_msg!())
	});

	macro_rules! funding_locked_msg {
		() => {{
			FundingLocked {
				channel_id: [0; 32],
				next_per_commitment_point: fake_public_key!()
			}
		}}
	}

	generate_handle_message_test!(handle_funding_locked, {
		Message::FundingLocked(funding_locked_msg!())
	});

	macro_rules! shutdown_msg {
		() => {{
			Shutdown {
				channel_id: [0; 32],
				scriptpubkey: Default::default()
			}
		}}
	}

	generate_handle_message_test!(handle_shutdown, {
		Message::Shutdown(shutdown_msg!())
	});

	macro_rules! closing_signed_msg {
		() => {{
			ClosingSigned {
				channel_id: [0; 32],
				fee_satoshis: 0,
				signature: fake_valid_sig!()
			}
		}}
	}

	generate_handle_message_test!(handle_closing_signed, {
		Message::ClosingSigned(closing_signed_msg!())
	});

	macro_rules! update_add_htlc_msg {
		() => {{
			UpdateAddHTLC {
				channel_id: [0; 32],
				htlc_id: 0,
				amount_msat: 0,
				payment_hash: PaymentHash([0; 32]),
				cltv_expiry: 0,
				onion_routing_packet: OnionPacket {
					version: 0,
					public_key: Ok(fake_public_key!()),
					hop_data: [0; 1300],
					hmac: [0; 32]
				}
			}
		}}
	}

	generate_handle_message_test!(handle_update_add_htlc, {
		Message::UpdateAddHTLC(update_add_htlc_msg!())
	});

	macro_rules! update_fulfill_htlc_msg {
		() => {{
			UpdateFulfillHTLC {
				channel_id: [0; 32],
				htlc_id: 0,
				payment_preimage: PaymentPreimage([0; 32])
			}
		}}
	}

	generate_handle_message_test!(handle_update_fulfill_htlc, {
		Message::UpdateFulfillHTLC(update_fulfill_htlc_msg!())
	});

	macro_rules! update_fail_htlc_msg {
		() => {{
			UpdateFailHTLC {
				channel_id: [0; 32],
				htlc_id: 0,
				reason: OnionErrorPacket { data: vec![] }
			}
		}}
	}

	generate_handle_message_test!(handle_update_fail_htlc, {
		Message::UpdateFailHTLC(update_fail_htlc_msg!())
	});

	macro_rules! update_fail_malformed_htlc_msg {
		() => {
			UpdateFailMalformedHTLC {
				channel_id: [0; 32],
				htlc_id: 0,
				sha256_of_onion: [0; 32],
				failure_code: 0
			}
		}
	}
	generate_handle_message_test!(handle_update_fail_malformed_htlc, {
		Message::UpdateFailMalformedHTLC(update_fail_malformed_htlc_msg!())
	});

	macro_rules! commitment_signed_msg {
		() => {{
			CommitmentSigned {
				channel_id: [0; 32],
				signature: fake_valid_sig!(),
				htlc_signatures: vec![]
			}
		}}
	}

	generate_handle_message_test!(handle_commitment_signed, {
		Message::CommitmentSigned(commitment_signed_msg!())
	});

	macro_rules! revoke_and_ack_msg {
		() => {{
			RevokeAndACK {
				channel_id: [0; 32],
				per_commitment_secret: [0; 32],
				next_per_commitment_point: fake_public_key!()
			}
		}}
	}

	generate_handle_message_test!(handle_revoke_and_ack, {
		Message::RevokeAndACK(revoke_and_ack_msg!())
	});

	macro_rules! update_fee_msg {
		() => {{
			UpdateFee {
				channel_id: [0; 32],
				feerate_per_kw: 0
			}
		}}
	}

	generate_handle_message_test!(handle_update_fee, {
		Message::UpdateFee(update_fee_msg!())
	});

	macro_rules! channel_reestablish_msg {
		() => {{
			ChannelReestablish {
				channel_id: [0; 32],
				next_local_commitment_number: 0,
				next_remote_commitment_number: 0,
				data_loss_protect: OptionalField::Absent
			}
		}}
	}

	generate_handle_message_test!(handle_channel_reestablish, {
		Message::ChannelReestablish(channel_reestablish_msg!())
	});

	macro_rules! announcement_signatures_msg {
		() => {{
			AnnouncementSignatures {
				channel_id: [0;32],
				short_channel_id: 0,
				node_signature: fake_valid_sig!(),
				bitcoin_signature: fake_valid_sig!()
			}
		}}
	}

	generate_handle_message_test!(handle_announcement_signatures, {
		Message::AnnouncementSignatures(announcement_signatures_msg!())
	});

	// Test that a post-Init connection:
	// * Returns an error if a ChannelAnnouncement message is received and the routing handler
	//   returns ErrorAction::DisconnectPeer
	// * calls the peer_disconnected channel manager callback
	// * is removed from get_peer_node_ids()
	// * disconnect_socket() is not called on the SocketDescriptor
	#[test]
	fn post_init_handle_channel_announcement_disconnect_peer() {
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_announcement_return = Err(msgs::LightningError { err: "", action: msgs::ErrorAction::DisconnectPeer { msg: None } });
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::with_routing_handler(routing_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		transport.borrow_mut().add_incoming_message(Message::ChannelAnnouncement(ChannelAnnouncement {
			node_signature_1: fake_valid_sig!(),
			node_signature_2: fake_valid_sig!(),
			bitcoin_signature_1: fake_valid_sig!(),
			bitcoin_signature_2: fake_valid_sig!(),
			contents: UnsignedChannelAnnouncement {
				features: ChannelFeatures::empty(),
				chain_hash: Default::default(),
				short_channel_id: 0,
				node_id_1: fake_public_key!(),
				node_id_2: fake_public_key!(),
				bitcoin_key_1: fake_public_key!(),
				bitcoin_key_2: fake_public_key!(),
				excess_data: vec![]
			}
		}));

		assert_read_event_errors!(peer_manager, &mut descriptor, false);
		assert!(peer_manager.get_peer_node_ids().is_empty());
		assert!(channel_handler_called!(&test_ctx, peer_disconnected));
		assert!(!descriptor.disconnect_called());
	}

	macro_rules! channel_announcement_msg {
		($channel_id: expr, $node_id_1: expr, $node_id_2: expr) => {{
			ChannelAnnouncement {
				node_signature_1: fake_valid_sig!(),
				node_signature_2: fake_valid_sig!(),
				bitcoin_signature_1: fake_valid_sig!(),
				bitcoin_signature_2: fake_valid_sig!(),
				contents: UnsignedChannelAnnouncement {
					features: ChannelFeatures::empty(),
					chain_hash: Default::default(),
					short_channel_id: $channel_id,
					node_id_1: $node_id_1,
					node_id_2: $node_id_2,
					bitcoin_key_1: fake_public_key!(),
					bitcoin_key_2: fake_public_key!(),
					excess_data: vec![]
				}
			}
		}}
	}

	// Test generator macro to reduce duplication across the broadcast message cases.
	// (test name, expression that returns a routing handler, message that will be queued, closure taking (peer_manager, descriptor) that does the validation)
	macro_rules! generate_broadcast_message_test {
		($test_name: ident, $routing_handler: expr, $message: expr, $validation: tt) => {
			#[test]
			fn $test_name() {
				let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::with_routing_handler($routing_handler);
				let mut descriptor = SocketDescriptorMock::new();
				let transport = new_connected_transport!(&test_ctx);
				let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

				transport.borrow_mut().add_incoming_message($message);

				$validation(peer_manager, descriptor)
			}
		}
	}

	// Test that a post-Init connection:
	// * Returns Ok if a ChannelAnnouncement message is received and the routing handler
	//   returns ErrorAction::IgnoreError
	generate_broadcast_message_test!(post_init_handle_channel_announcement_ignore_error, {
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_announcement_return = Err(msgs::LightningError { err: "", action: msgs::ErrorAction::IgnoreError });
		routing_handler
	},
	Message::ChannelAnnouncement(channel_announcement_msg!(0, fake_public_key!(), fake_public_key!())),
	(| peer_manager: PeerManagerImpl<SocketDescriptorMock, &ChannelMessageHandlerTestSpy, &RoutingMessageHandlerTestStub, &TestLogger, &RefCell<TransportStub>>, mut descriptor |
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false))
	));

	// Test that a post-Init connection:
	// * Returns Ok if a ChannelAnnouncement message is received and the routing handler
	//   returns ErrorAction::IgnoreError
	// * Enqueues an ErrorMessage for send that is flushed during the next process_events()
	generate_broadcast_message_test!(post_init_handle_channel_announcement_send_error_message, {
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_announcement_return = Err(msgs::LightningError { err: "", action: msgs::ErrorAction::SendErrorMessage { msg: ErrorMessage { channel_id: [0; 32], data: "".to_string() } } });
		routing_handler
	},
	Message::ChannelAnnouncement(channel_announcement_msg!(0, fake_public_key!(), fake_public_key!())),
	(| peer_manager: PeerManagerImpl<SocketDescriptorMock, &ChannelMessageHandlerTestSpy, &RoutingMessageHandlerTestStub, &TestLogger, &RefCell<TransportStub>>, mut descriptor | {
			assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
			let recording = descriptor.get_recording();
			assert_matches_message!(&recording[0].0, Message::Error(_))
		}
	));

	// Test that a post-Init connection:
	// * Returns Ok if a ChannelAnnouncement message is received and the routing handler
	//   returns true
	generate_broadcast_message_test!(post_init_handle_channel_announcement_should_forward, {
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_announcement_return = Ok(true);
		routing_handler
	},
	Message::ChannelAnnouncement(channel_announcement_msg!(0, fake_public_key!(), fake_public_key!())),
	(| peer_manager: PeerManagerImpl<SocketDescriptorMock, &ChannelMessageHandlerTestSpy, &RoutingMessageHandlerTestStub, &TestLogger, &RefCell<TransportStub>>, mut descriptor | {
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
		}
	));

	// Test that a post-Init connection:
	// * Returns Ok if a ChannelAnnouncement message is received and the routing handler
	//   returns false
	generate_broadcast_message_test!(post_init_handle_channel_announcement_should_not_forward, {
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_announcement_return = Ok(false);
		routing_handler
	},
	Message::ChannelAnnouncement(channel_announcement_msg!(0, fake_public_key!(), fake_public_key!())),
	(| peer_manager: PeerManagerImpl<SocketDescriptorMock, &ChannelMessageHandlerTestSpy, &RoutingMessageHandlerTestStub, &TestLogger, &RefCell<TransportStub>>, mut descriptor | {
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
		}
	));

	macro_rules! node_announcement_msg {
		() => {{
			NodeAnnouncement {
				signature: fake_valid_sig!(),
				contents: UnsignedNodeAnnouncement {
					features: NodeFeatures::empty(),
					timestamp: 0,
					node_id: fake_public_key!(),
					rgb: [0; 3],
					alias: [0; 32],
					addresses: vec![],
					excess_address_data: vec![],
					excess_data: vec![]
				}
			}
		}}
	}

	// Test that a post-Init connection:
	// * Returns Ok if a NodeAnnouncement message is received and the routing handler
	//   returns ErrorAction::IgnoreError
	generate_broadcast_message_test!(post_init_handle_node_announcement_ignore_error, {
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_node_announcement_return = Err(msgs::LightningError { err: "", action: msgs::ErrorAction::IgnoreError });
		routing_handler
	},
	Message::NodeAnnouncement(node_announcement_msg!()),
	(| peer_manager: PeerManagerImpl<SocketDescriptorMock, &ChannelMessageHandlerTestSpy, &RoutingMessageHandlerTestStub, &TestLogger, &RefCell<TransportStub>>, mut descriptor |
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false))
	));

	// Test that a post-Init connection:
	// * Returns Ok if a NodeAnnouncement message is received and the routing handler
	//   returns ErrorAction::IgnoreError
	// * Enqueues an ErrorMessage for send that is flushed during the next process_events()
	generate_broadcast_message_test!(post_init_handle_node_announcement_send_error_message, {
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_node_announcement_return = Err(msgs::LightningError { err: "", action: msgs::ErrorAction::SendErrorMessage { msg: ErrorMessage { channel_id: [0; 32], data: "".to_string() } } });
		routing_handler
	},
	Message::NodeAnnouncement(node_announcement_msg!()),
	(| peer_manager: PeerManagerImpl<SocketDescriptorMock, &ChannelMessageHandlerTestSpy, &RoutingMessageHandlerTestStub, &TestLogger, &RefCell<TransportStub>>, mut descriptor | {
			assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
			let recording = descriptor.get_recording();
			assert_matches_message!(&recording[0].0, Message::Error(_))
		}
	));

	// Test that a post-Init connection:
	// * Returns Ok if a NodeAnnouncement message is received and the routing handler
	//   returns true
	generate_broadcast_message_test!(post_init_handle_node_announcement_should_forward, {
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_node_announcement_return = Ok(true);
		routing_handler
	},
	Message::NodeAnnouncement(node_announcement_msg!()),
	(| peer_manager: PeerManagerImpl<SocketDescriptorMock, &ChannelMessageHandlerTestSpy, &RoutingMessageHandlerTestStub, &TestLogger, &RefCell<TransportStub>>, mut descriptor | {
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
		}
	));

	// Test that a post-Init connection:
	// * Returns Ok if a NodeAnnouncement message is received and the routing handler
	//   returns false
	generate_broadcast_message_test!(post_init_handle_node_announcement_should_not_forward, {
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_node_announcement_return = Ok(false);
		routing_handler
	},
	Message::NodeAnnouncement(node_announcement_msg!()),
	(| peer_manager: PeerManagerImpl<SocketDescriptorMock, &ChannelMessageHandlerTestSpy, &RoutingMessageHandlerTestStub, &TestLogger, &RefCell<TransportStub>>, mut descriptor | {
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
		}
	));

	macro_rules! channel_update_msg {
		() => {{
			ChannelUpdate {
				signature: fake_valid_sig!(),
				contents: UnsignedChannelUpdate {
					chain_hash: Default::default(),
					short_channel_id: 0,
					timestamp: 0,
					flags: 0,
					cltv_expiry_delta: 0,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 0,
					excess_data: vec![]
				}
			}
		}}
	}

	// Test that a post-Init connection:
	// * Returns Ok if a ChannelUpdate message is received and the routing handler
	//   returns ErrorAction::IgnoreError
	generate_broadcast_message_test!(post_init_handle_channel_update_ignore_error, {
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_update_return = Err(msgs::LightningError { err: "", action: msgs::ErrorAction::IgnoreError });
		routing_handler
	},
	Message::ChannelUpdate(channel_update_msg!()),
	(| peer_manager: PeerManagerImpl<SocketDescriptorMock, &ChannelMessageHandlerTestSpy, &RoutingMessageHandlerTestStub, &TestLogger, &RefCell<TransportStub>>, mut descriptor |
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false))
	));

	// Test that a post-Init connection:
	// * Returns Ok if a ChannelUpdate message is received and the routing handler
	//   returns ErrorAction::IgnoreError
	// * Enqueues an ErrorMessage for send that is flushed during the next process_events()
	generate_broadcast_message_test!(post_init_handle_channel_update_send_error_message, {
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_update_return = Err(msgs::LightningError { err: "", action: msgs::ErrorAction::SendErrorMessage { msg: ErrorMessage { channel_id: [0; 32], data: "".to_string() } } });
		routing_handler
	},
	Message::ChannelUpdate(channel_update_msg!()),
	(| peer_manager: PeerManagerImpl<SocketDescriptorMock, &ChannelMessageHandlerTestSpy, &RoutingMessageHandlerTestStub, &TestLogger, &RefCell<TransportStub>>, mut descriptor | {
			assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
			let recording = descriptor.get_recording();
			assert_matches_message!(&recording[0].0, Message::Error(_))
		}
	));

	// Test that a post-Init connection:
	// * Returns Ok if a ChannelUpdate message is received and the routing handler
	//   returns true
	generate_broadcast_message_test!(post_init_handle_channel_update_should_forward, {
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_update_return = Ok(true);
		routing_handler
	},
	Message::ChannelUpdate(channel_update_msg!()),
	(| peer_manager: PeerManagerImpl<SocketDescriptorMock, &ChannelMessageHandlerTestSpy, &RoutingMessageHandlerTestStub, &TestLogger, &RefCell<TransportStub>>, mut descriptor | {
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
		}
	));

	// Test that a post-Init connection:
	// * Returns Ok if a ChannelUpdate message is received and the routing handler
	//   returns false
	generate_broadcast_message_test!(post_init_handle_channel_update_should_not_forward, {
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_update_return = Ok(false);
		routing_handler
	},
	Message::ChannelUpdate(channel_update_msg!()),
	(| peer_manager: PeerManagerImpl<SocketDescriptorMock, &ChannelMessageHandlerTestSpy, &RoutingMessageHandlerTestStub, &TestLogger, &RefCell<TransportStub>>, mut descriptor | {
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
		}
	));

	//  _____                 _     _____         _   _
	// | ____|_   _____ _ __ | |_  |_   _|__  ___| |_(_)_ __   __ _
	// |  _| \ \ / / _ \ '_ \| __|   | |/ _ \/ __| __| | '_ \ / _` |
	// | |___ \ V /  __/ | | | |_    | |  __/\__ \ |_| | | | | (_| |
	// |_____| \_/ \___|_| |_|\__|   |_|\___||___/\__|_|_| |_|\__, |
	//                                                         |___/

	// To reduce test expansion, the unknown, unconnected, and connected variants are only run
	// on one event type. All handlers use the same accessor to retrieve the connected node so one
	// test of those paths should be sufficient. The initialized variant is run on all types which
	// is where the interesting code is run. Once features are added to take action on unconnected
	// nodes, this should be revisited.

	// Test that a post-Init connection:
	// * does not send an OpenChannel message when it receives a SendOpenChannel event if the peer
	//   is unknown
	#[test]
	fn unknown_node_send_open_channel_event() {
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(MessageSendEvent::SendOpenChannel {
			node_id: fake_public_key!(),
			msg: open_channel_msg!()
		});
		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();
		assert!(descriptor.get_recording().is_empty());
	}

	// Test that a post-Init connection:
	// * does not send an OpenChannel message when it receives a SendOpenChannel event if the peer
	//   is known, but the NOISE handshake is not complete
	#[test]
	fn unconnected_transport_send_open_channel_event() {
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(MessageSendEvent::SendOpenChannel {
			node_id: fake_public_key!(),
			msg: open_channel_msg!()
		});
		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
		let descriptor = SocketDescriptorMock::new();
		let mut transport = new_unconnected_transport!();
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		new_outbound!(peer_manager, descriptor, &mut transport);

		peer_manager.process_events();

		assert!(descriptor.get_recording().is_empty());
	}

	// Test that a post-Init connection:
	// * does not send an OpenChannel message when it receives a SendOpenChannel event if the peer
	//   is known, but the INIT message has not been received
	#[test]
	fn connected_transport_send_open_channel_event() {
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(MessageSendEvent::SendOpenChannel {
			node_id: fake_public_key!(),
			msg: open_channel_msg!()
		});
		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
		let descriptor = SocketDescriptorMock::new();
		let mut transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		new_outbound!(peer_manager, descriptor, &mut transport);

		peer_manager.process_events();

		assert!(descriptor.get_recording().is_empty());
	}

	// Test generator macro to reduce duplication across the event handlers that just enqueue a message
	// (test name, expression that returns a routing handler, message that will be queued, closure taking (peer_manager, descriptor) that does the validation)
	macro_rules! generate_event_handler_test {
		($test_name: ident, $event: expr, $expected_message: pat) => {
			#[test]
			fn $test_name() {
				let channel_handler = TestChannelMessageHandler::new();
				channel_handler.pending_events.lock().unwrap().push($event);

				let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
				let mut descriptor = SocketDescriptorMock::new();
				let transport = new_connected_transport!(&test_ctx);
				let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

				peer_manager.process_events();

				let recording = descriptor.get_recording();
				assert_matches_message!(&recording[0].0, $expected_message);
			}
		}
	}

	// Test that a post-Init connection:
	// * sends an OpenChannel message when it receives a SendOpenChannel event for an initialized node
	generate_event_handler_test!(post_init_send_open_channel,
		SendOpenChannel {
			node_id: test_ctx_their_node_id!(),
			msg: open_channel_msg!(),
		},
		Message::OpenChannel(_)
	);

	// Test that a post-Init connection:
	// * sends an AcceptChannel message when it receives a SendAcceptChannel event for an initialized node
	generate_event_handler_test!(post_init_send_accept_channel,
		SendAcceptChannel {
			node_id: test_ctx_their_node_id!(),
			msg: accept_channel_msg!(),
		},
		Message::AcceptChannel(_)
	);

	// Test that a post-Init connection:
	// * sends an AcceptChannel message when it receives a SendAcceptChannel event for an initialized node
	generate_event_handler_test!(post_init_send_funding_created,
		SendFundingCreated {
			node_id: test_ctx_their_node_id!(),
			msg: funding_created_msg!(),
		},
		Message::FundingCreated(_)
	);

	// Test that a post-Init connection:
	// * sends an FundingSigned message when it receives a SendFundingSigned event for an initialized node
	generate_event_handler_test!(post_init_send_funding_signed,
		SendFundingSigned {
			node_id: test_ctx_their_node_id!(),
			msg: funding_signed_msg!(),
		},
		Message::FundingSigned(_)
	);

	// Test that a post-Init connection:
	// * sends an FundingLocked message when it receives a SendFundingLocked event for an initialized node
	generate_event_handler_test!(post_init_send_funding_locked,
		SendFundingLocked {
			node_id: test_ctx_their_node_id!(),
			msg: funding_locked_msg!(),
		},
		Message::FundingLocked(_)
	);

	// Test that a post-Init connection:
	// * sends an AnnouncementSignatures message when it receives a SendAnnouncementSignatures event for an initialized node
	generate_event_handler_test!(post_init_send_announcement_signatures,
		SendAnnouncementSignatures {
			node_id: test_ctx_their_node_id!(),
			msg: announcement_signatures_msg!(),
		},
		Message::AnnouncementSignatures(_)
	);

	// Test that a post-Init connection:
	// * sends an RevokeAndACK message when it receives a SendRevokeAndACK event for an initialized node
	generate_event_handler_test!(post_init_send_revoke_ack,
		SendRevokeAndACK {
			node_id: test_ctx_their_node_id!(),
			msg: revoke_and_ack_msg!(),
		},
		Message::RevokeAndACK(_)
	);

	// Test that a post-Init connection:
	// * sends an ClosingSigned message when it receives a SendClosingSigned event for an initialized node
	generate_event_handler_test!(post_init_send_closing_signed,
		SendClosingSigned {
			node_id: test_ctx_their_node_id!(),
			msg: closing_signed_msg!(),
		},
		Message::ClosingSigned(_)
	);

	// Test that a post-Init connection:
	// * sends an Shutdown message when it receives a Shutdown event for an initialized node
	generate_event_handler_test!(post_init_send_shutdown,
		SendShutdown {
			node_id: test_ctx_their_node_id!(),
			msg: shutdown_msg!(),
		},
		Message::Shutdown(_)
	);

	// Test that a post-Init connection:
	// * sends an ChannelReestablish message when it receives a SendChannelReestablish event for an initialized node
	generate_event_handler_test!(post_init_send_channel_reestablish,
		SendChannelReestablish {
			node_id: test_ctx_their_node_id!(),
			msg: channel_reestablish_msg!()
		},
		Message::ChannelReestablish(_)
	);

	// Test that a post-Init connection:
	// * sends relevant HTLC messages when it receives a UpdateHTLC event for an initialized node
	#[test]
	fn post_init_send_update_htlcs() {
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(UpdateHTLCs {
			node_id: test_ctx_their_node_id!(),
			updates: CommitmentUpdate {
				update_add_htlcs: vec![update_add_htlc_msg!()],
				update_fulfill_htlcs: vec![update_fulfill_htlc_msg!()],
				update_fail_htlcs: vec![update_fail_htlc_msg!()],
				update_fail_malformed_htlcs: vec![update_fail_malformed_htlc_msg!()],
				update_fee: Some(update_fee_msg!()),
				commitment_signed: commitment_signed_msg!()
			}
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();

		let recording = descriptor.get_recording();
		assert_matches_message!(&recording[0].0, Message::UpdateAddHTLC(_));
		assert_matches_message!(&recording[1].0, Message::UpdateFulfillHTLC(_));
		assert_matches_message!(&recording[2].0, Message::UpdateFailHTLC(_));
		assert_matches_message!(&recording[3].0, Message::UpdateFailMalformedHTLC(_));
		assert_matches_message!(&recording[4].0, Message::UpdateFee(_));
		assert_matches_message!(&recording[5].0, Message::CommitmentSigned(_));
	}

	// Test that a post-Init connection:
	// * sends nothing when it receives a BroadcastChannelAnnouncement if the route_handler.handle_channel_announcement errors
	#[test]
	fn post_init_broadcast_channel_announcement_route_handler_handle_announcement_errors() {
		let channel_handler = TestChannelMessageHandler::new();
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_announcement_return = Err(msgs::LightningError { err: "", action: msgs::ErrorAction::IgnoreError });
		channel_handler.pending_events.lock().unwrap().push(BroadcastChannelAnnouncement {
			msg: channel_announcement_msg!(0, fake_public_key!(), fake_public_key!()),
			update_msg: channel_update_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_and_routing(channel_handler, routing_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();
		assert!(descriptor.get_recording().is_empty());
	}

	// Test that a post-Init connection:
	// * sends nothing when it receives a BroadcastChannelAnnouncement if the route_handler.handle_channel_update errors
	#[test]
	fn post_init_broadcast_channel_announcement_route_handler_handle_update_errors() {
		let channel_handler = TestChannelMessageHandler::new();
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_update_return = Err(msgs::LightningError { err: "", action: msgs::ErrorAction::IgnoreError });
		channel_handler.pending_events.lock().unwrap().push(BroadcastChannelAnnouncement {
			msg: channel_announcement_msg!(0, fake_public_key!(), fake_public_key!()),
			update_msg: channel_update_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_and_routing(channel_handler, routing_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();
		assert!(descriptor.get_recording().is_empty());
	}

	// Test that a post-Init connection:
	// * sends nothing when it receives a BroadcastChannelAnnouncement if the route_handler.handle_channel_announcement returns false
	// XXXBUG: Implementation does not check return value of handle_channel_announcement, only that it didn't error
	#[test]
	fn post_init_broadcast_channel_announcement_route_handler_handle_announcement_returns_false() {
		let channel_handler = TestChannelMessageHandler::new();
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_announcement_return = Ok(false);
		channel_handler.pending_events.lock().unwrap().push(BroadcastChannelAnnouncement {
			msg: channel_announcement_msg!(0, fake_public_key!(), fake_public_key!()),
			update_msg: channel_update_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_and_routing(channel_handler, routing_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();
		// assert!(descriptor.get_recording().is_empty());
	}

	// Test that a post-Init connection:
	// * sends nothing when it receives a BroadcastChannelAnnouncement if the route_handler.handle_channel_update returns false
	// XXXBUG: Implementation does not check return value of handle_channel_update, only that it didn't error
	#[test]
	fn post_init_broadcast_channel_announcement_route_handle_update_returns_false() {
		let channel_handler = TestChannelMessageHandler::new();
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_update_return = Ok(false);
		channel_handler.pending_events.lock().unwrap().push(BroadcastChannelAnnouncement {
			msg: channel_announcement_msg!(0, fake_public_key!(), fake_public_key!()),
			update_msg: channel_update_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_and_routing(channel_handler, routing_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();
		// assert!(descriptor.get_recording().is_empty());
	}

	// To reduce test expansion, the unconnected and connected transport tests are only run on one
	// broadcast variant. All broadcast implementations use the same API to determine whether or not
	// the peer wants the announcement forwarded.

	// Test that a post-Init connection:
	// * sends nothing when it receives a BroadcastChannelAnnouncement if the peer has not completed the NOISE handshake
	#[test]
	fn unconnected_transport_broadcast_channel_announcement() {
		let channel_handler = TestChannelMessageHandler::new();
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_update_return = Ok(false);
		channel_handler.pending_events.lock().unwrap().push(BroadcastChannelAnnouncement {
			msg: channel_announcement_msg!(0, fake_public_key!(), fake_public_key!()),
			update_msg: channel_update_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_and_routing(channel_handler, routing_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_unconnected_transport!();
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		new_outbound!(peer_manager, &mut descriptor, &transport);

		peer_manager.process_events();
		assert!(descriptor.get_recording().is_empty());
	}

	// Test that a post-Init connection:
	// * sends nothing when it receives a BroadcastChannelAnnouncement if the peer has not received an INIT message
	#[test]
	fn connected_transport_broadcast_channel_announcement() {
		let channel_handler = TestChannelMessageHandler::new();
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_update_return = Ok(false);
		channel_handler.pending_events.lock().unwrap().push(BroadcastChannelAnnouncement {
			msg: channel_announcement_msg!(0, fake_public_key!(), fake_public_key!()),
			update_msg: channel_update_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_and_routing(channel_handler, routing_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		new_outbound!(peer_manager, &mut descriptor, &transport);

		peer_manager.process_events();
		assert!(descriptor.get_recording().is_empty());
	}

	// Test that a post-Init connection:
	// * sends nothing when it receives a BroadcastChannelAnnouncement if the peer is initialized,
	//   but Peer::should_forward_channel_announcement returns false
	#[test]
	fn connected_transport_broadcast_channel_announcement_short_channel_id_larger_than_current_sync() {
		let channel_handler = TestChannelMessageHandler::new();
		let routing_handler = RoutingMessageHandlerTestStub::new();
		channel_handler.pending_events.lock().unwrap().push(BroadcastChannelAnnouncement {
			msg: channel_announcement_msg!(10000, fake_public_key!(), fake_public_key!()),
			update_msg: channel_update_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_and_routing(channel_handler, routing_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_for_test!(&test_ctx);
		new_outbound!(peer_manager, &mut descriptor, &transport);

		// Use an Init sequence with initial_routing_sync and use an arbitrarily high short
		// channel_id in the channel_announcement_msg to create the state. This test knows a bit too
		// much and future refactoring can make this much better.
		transport.borrow_mut().add_incoming_message(Message::Init(Init { features: InitFeatures::known() }));
		peer_manager.process_events();
		assert!(descriptor.get_recording().is_empty());
	}

	// Test that a post-Init connection:
	// * sends nothing when it receives a BroadcastChannelAnnouncement if the peer is node_id_1
	#[test]
	fn post_init_broadcast_channel_announcement_skip_node_id_1() {
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(BroadcastChannelAnnouncement {
			msg: channel_announcement_msg!(0, test_ctx_their_node_id!(), fake_public_key!()),
			update_msg: channel_update_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();
		assert!(descriptor.get_recording().is_empty());
	}

	// Test that a post-Init connection:
	// * sends nothing when it receives a BroadcastChannelAnnouncement if the peer is node_id_2
	#[test]
	fn post_init_broadcast_channel_announcement_skip_node_id_2() {
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(BroadcastChannelAnnouncement {
			msg: channel_announcement_msg!(0, fake_public_key!(), test_ctx_their_node_id!()),
			update_msg: channel_update_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();
		assert!(descriptor.get_recording().is_empty());
	}

	// Test that a post-Init connection:
	// * sends the relevant messages when it receives a BroadcastChannelAnnouncement
	#[test]
	fn post_init_broadcast_channel_announcement() {
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(BroadcastChannelAnnouncement {
			msg: channel_announcement_msg!(0, fake_public_key!(), fake_public_key!()),
			update_msg: channel_update_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();

		let recording = descriptor.get_recording();
		assert_matches_message!(&recording[0].0, Message::ChannelAnnouncement(_));
		assert_matches_message!(&recording[1].0, Message::ChannelUpdate(_));
	}

	// Test that a post-Init connection:
	// * sends nothing when it receives a BroadcastNodeAnnouncement if the route_handler.handle_node_announcement errors
	#[test]
	fn post_init_broadcast_node_announcement_route_handler_handle_announcement_errors() {
		let channel_handler = TestChannelMessageHandler::new();
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_node_announcement_return = Err(msgs::LightningError { err: "", action: msgs::ErrorAction::IgnoreError });
		channel_handler.pending_events.lock().unwrap().push(BroadcastNodeAnnouncement {
			msg: node_announcement_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_and_routing(channel_handler, routing_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();
		assert!(descriptor.get_recording().is_empty());
	}

	// Test that a post-Init connection:
	// * sends nothing when it receives a BroadcastNodeAnnouncement if the route_handler.handle_node_announcement returns false
	// XXXBUG: Implementation does not check return value of handle_node_announcement, only that it didn't error
	#[test]
	fn post_init_broadcast_node_announcement_route_handler_handle_announcement_returns_false() {
		let channel_handler = TestChannelMessageHandler::new();
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_node_announcement_return = Ok(false);
		channel_handler.pending_events.lock().unwrap().push(BroadcastNodeAnnouncement {
			msg: node_announcement_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_and_routing(channel_handler, routing_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();
		// assert!(descriptor.get_recording().is_empty());
	}

	// Test that a post-Init connection:
	// * sends the relevant messages when it receives a BroadcastNodeAnnouncement
	#[test]
	fn post_init_broadcast_node_announcement() {
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(BroadcastNodeAnnouncement {
			msg: node_announcement_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();

		let recording = descriptor.get_recording();
		assert_matches_message!(&recording[0].0, Message::NodeAnnouncement(_));
	}


	// Test that a post-Init connection:
	// * sends nothing when it receives a BroadcastChannelUpdate if the route_handler.handle_channel_update errors
	#[test]
	fn post_init_broadcast_channel_update_route_handler_handle_update_errors() {
		let channel_handler = TestChannelMessageHandler::new();
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_update_return = Err(msgs::LightningError { err: "", action: msgs::ErrorAction::IgnoreError });
		channel_handler.pending_events.lock().unwrap().push(BroadcastChannelUpdate {
			msg: channel_update_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_and_routing(channel_handler, routing_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();
		assert!(descriptor.get_recording().is_empty());
	}

	// Test that a post-Init connection:
	// * sends nothing when it receives a BroadcastChannelUpdate if the route_handler.handle_channel_update returns false
	// XXXBUG: Implementation does not check return value of handle_node_announcement, only that it didn't error
	#[test]
	fn post_init_broadcast_channel_update_route_handler_handle_update_returns_false() {
		let channel_handler = TestChannelMessageHandler::new();
		let mut routing_handler = RoutingMessageHandlerTestStub::new();
		routing_handler.handle_channel_update_return = Ok(false);
		channel_handler.pending_events.lock().unwrap().push(BroadcastChannelUpdate {
			msg: channel_update_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_and_routing(channel_handler, routing_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();
		// assert!(descriptor.get_recording().is_empty());
	}

	// Test that a post-Init connection:
	// * sends the relevant messages when it receives a BroadcastChannelAnnouncement
	#[test]
	fn post_init_broadcast_channel_update() {
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(BroadcastChannelUpdate {
			msg: channel_update_msg!()
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();

		let recording = descriptor.get_recording();
		assert_matches_message!(&recording[0].0, Message::ChannelUpdate(_));
	}

	// Test that a post-Init connection:
	// * calls the correct route handler callback when it receives a PaymentFailureNetworkUpdate event
	#[test]
	fn post_init_payment_failure_network_update() {
		let routing_handler = RoutingMessageHandlerTestSpy::new();
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(PaymentFailureNetworkUpdate {
			update: HTLCFailChannelUpdate::ChannelUpdateMessage {
				msg: channel_update_msg!()
			}
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestSpy>::with_channel_and_routing(channel_handler, routing_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();

		assert!(route_handler_called!(&test_ctx, handle_htlc_fail_channel_update));
	}

	// Test that a post-Init connection:
	// * When it receives a HandleErrorEvent::DisconnectPeer for an unknown peer
	// * ignores it
	#[test]
	fn post_init_handle_error_event_disconnect_unknown_peer() {
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(HandleError {
			node_id: fake_public_key!(),
			action: ErrorAction::DisconnectPeer { msg: None }
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();

		assert!(!descriptor.disconnect_called());
		assert!(descriptor.get_recording().is_empty());
		assert!(!peer_manager.get_peer_node_ids().is_empty());
	}

	// Test that a post-Init connection:
	// * When it receives a HandleErrorEvent::DisconnectPeer for an initialized peer w/ no message
	// * node_id is no longer in get_peer_node_ids()
	// * socket_disconnected() is called on the SocketDescriptor
	#[test]
	fn post_init_handle_error_event_disconnect_no_message() {
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(HandleError {
			node_id: test_ctx_their_node_id!(),
			action: ErrorAction::DisconnectPeer { msg: None }
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();

		assert!(descriptor.disconnect_called());
		assert!(descriptor.get_recording().is_empty());
		assert!(peer_manager.get_peer_node_ids().is_empty());
	}

	// Test that a post-Init connection:
	// * When it receives a HandleErrorEvent::DisconnectPeer for an initialized peer w/ a message
	// * node_id is no longer in get_peer_node_ids()
	// * error message is sent through SocketDescriptor (attempted)
	// * socket_disconnected() is called on the SocketDescriptor
	#[test]
	fn post_init_handle_error_event_disconnect_message() {
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(HandleError {
			node_id: test_ctx_their_node_id!(),
			action: ErrorAction::DisconnectPeer { msg: Some(ErrorMessage {
				channel_id: [0; 32],
				data: "".to_string()
			})}
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();

		let recording = descriptor.get_recording();
		assert_matches_message!(&recording[0].0, Message::Error(_));
		assert!(descriptor.disconnect_called());
		assert!(peer_manager.get_peer_node_ids().is_empty());
	}

	// Test that a post-Init connection:
	// * When it receives a HandleErrorEvent::IgnoreError for an initialized peer
	// * is ignored
	#[test]
	fn post_init_handle_error_event_ignore_error() {
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(HandleError {
			node_id: test_ctx_their_node_id!(),
			action: ErrorAction::IgnoreError
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();

		assert!(!descriptor.disconnect_called());
		assert!(descriptor.get_recording().is_empty());
		assert!(!peer_manager.get_peer_node_ids().is_empty());
	}

	// Test that a post-Init connection:
	// * When it receives a HandleErrorEvent::SendErrorMessage for an initialized peer
	// * error message is sent through SocketDescriptor
	#[test]
	fn post_init_handle_error_event_send_error_message() {
		let channel_handler = TestChannelMessageHandler::new();
		channel_handler.pending_events.lock().unwrap().push(HandleError {
			node_id: test_ctx_their_node_id!(),
			action: ErrorAction::SendErrorMessage {
				msg: ErrorMessage { channel_id: [0; 32], data: "".to_string() }
			}
		});

		let test_ctx = TestCtx::<TestChannelMessageHandler, RoutingMessageHandlerTestStub>::with_channel_handler(channel_handler);
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.process_events();

		let recording = descriptor.get_recording();
		assert_matches_message!(&recording[0].0, Message::Error(_));
		assert!(!descriptor.disconnect_called());
		assert!(!peer_manager.get_peer_node_ids().is_empty());
	}

	//  ____  _               _____         _   _
	// |  _ \(_)_ __   __ _  |_   _|__  ___| |_(_)_ __   __ _
	// | |_) | | '_ \ / _` |   | |/ _ \/ __| __| | '_ \ / _` |
	// |  __/| | | | | (_| |   | |  __/\__ \ |_| | | | | (_| |
	// |_|   |_|_| |_|\__, |   |_|\___||___/\__|_|_| |_|\__, |
	//                 |___/                             |___/

	// Test that a post-Init connection:
	// * queues a Pong when it receives a Ping
	#[test]
	fn post_init_ping_creates_pong() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		transport.borrow_mut().add_incoming_message(Message::Ping(Ping { ponglen: 1, byteslen: 0 }));

		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));

		peer_manager.process_events();

		let recording = descriptor.get_recording();
		assert_matches_message!(&recording[0].0, Message::Pong(Pong { byteslen: 1}));
	}

	// Test that a post-Init connection:
	// * ignores a Pong with ponglen > 65531
	#[test]
	fn post_init_ping_ignores_large_pong() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		transport.borrow_mut().add_incoming_message(Message::Ping(Ping { ponglen: 65532, byteslen: 0 }));
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));
		descriptor.assert_called_with(vec![]);

		peer_manager.process_events();
		descriptor.assert_called_with(vec![]);
	}

	// Test that a post-Init connection:
	// * timer_tick_occurred() generates a Ping
	#[test]
	fn post_init_timer_tick_occurred_generates_ping() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.timer_tick_occured();

		let recording = descriptor.get_recording();
		assert_matches_message!(&recording[0].0, Message::Ping(_));
	}

	// Test that a post-Init connection:
	// * timer_tick_occurred() disconnects if a Pong was not received
	// * disconnected node is not in get_peer_node_ids()
	// * calls the peer_disconnected channel manager callback
	#[test]
	fn post_init_ping_no_pong_disconnects() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.timer_tick_occured();

		// Elapsed time with no Pong

		peer_manager.timer_tick_occured();

		assert!(descriptor.disconnect_called());
		assert!(!peer_manager.get_peer_node_ids().contains(&test_ctx.their_node_id));
		assert!(channel_handler_called!(&test_ctx, peer_disconnected));
	}

	// Test that a post-Init connection:
	// * timer_tick_occurred() does not disconnect if a Pong was received
	#[test]
	fn post_init_ping_with_pong() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.timer_tick_occured();

		transport.borrow_mut().add_incoming_message(Message::Pong(Pong { byteslen: 64 }));
		assert_matches!(peer_manager.read_event(&mut descriptor, &[]), Ok(false));

		// Should notice the Pong and resend Ping
		peer_manager.timer_tick_occured();

		let recording = descriptor.get_recording();
		assert_matches_message!(&recording[1].0, Message::Ping(_));
		assert!(peer_manager.get_peer_node_ids().contains(&test_ctx.their_node_id));
	}

	// Test that a post-Init connection:
	// * socket_disconnected() removes the node_id from get_peer_node_ids()
	// * does not call disconnect_socket() on the SocketDescriptor
	// * calls the peer_disconnected channel manager callback
	#[test]
	fn post_init_socket_disconnected() {
		let test_ctx = TestCtx::<ChannelMessageHandlerTestSpy, RoutingMessageHandlerTestStub>::new();
		let mut descriptor = SocketDescriptorMock::new();
		let transport = new_connected_transport!(&test_ctx);
		let peer_manager = new_peer_manager_post_init!(&test_ctx, &mut descriptor, &transport);

		peer_manager.socket_disconnected(&descriptor);

		assert!(peer_manager.get_peer_node_ids().is_empty());
		assert!(!descriptor.disconnect_called());
		assert!(channel_handler_called!(&test_ctx, peer_disconnected));
	}
}

#[cfg(test)]
mod tests {
	use ln::peers::handler::{PeerManager, MessageHandler, SocketDescriptor};
	use ln::msgs;
	use util::events;
	use util::test_utils;

	use bitcoin::secp256k1::Secp256k1;
	use bitcoin::secp256k1::key::{SecretKey, PublicKey};

	use rand::{thread_rng, Rng};

	use std;
	use std::sync::{Arc, Mutex};
	use std::sync::atomic::Ordering;

	#[derive(Clone)]
	struct FileDescriptor {
		fd: u16,
		outbound_data: Arc<Mutex<Vec<u8>>>,
	}
	impl PartialEq for FileDescriptor {
		fn eq(&self, other: &Self) -> bool {
			self.fd == other.fd
		}
	}
	impl Eq for FileDescriptor { }
	impl std::hash::Hash for FileDescriptor {
		fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
			self.fd.hash(hasher)
		}
	}

	impl SocketDescriptor for FileDescriptor {
		fn send_data(&mut self, data: &[u8], _resume_read: bool) -> usize {
			self.outbound_data.lock().unwrap().extend_from_slice(data);
			data.len()
		}

		fn disconnect_socket(&mut self) {}
	}

	struct PeerManagerCfg {
		chan_handler: test_utils::TestChannelMessageHandler,
		routing_handler: test_utils::TestRoutingMessageHandler,
		logger: test_utils::TestLogger,
	}

	fn create_peermgr_cfgs(peer_count: usize) -> Vec<PeerManagerCfg> {
		let mut cfgs = Vec::new();
		for _ in 0..peer_count {
			cfgs.push(
				PeerManagerCfg{
					chan_handler: test_utils::TestChannelMessageHandler::new(),
					logger: test_utils::TestLogger::new(),
					routing_handler: test_utils::TestRoutingMessageHandler::new(),
				}
			);
		}

		cfgs
	}

	fn create_network<'a>(peer_count: usize, cfgs: &'a Vec<PeerManagerCfg>) -> Vec<PeerManager<FileDescriptor, &'a test_utils::TestChannelMessageHandler, &'a test_utils::TestRoutingMessageHandler, &'a test_utils::TestLogger>> {
		let mut peers = Vec::new();
		let mut rng = thread_rng();
		let mut ephemeral_bytes = [0; 32];
		rng.fill_bytes(&mut ephemeral_bytes);

		for i in 0..peer_count {
			let node_id = {
				let mut key_slice = [0;32];
				rng.fill_bytes(&mut key_slice);
				SecretKey::from_slice(&key_slice).unwrap()
			};
			let msg_handler = MessageHandler { chan_handler: &cfgs[i].chan_handler, route_handler: &cfgs[i].routing_handler };
			let peer = PeerManager::new(msg_handler, node_id, &ephemeral_bytes, &cfgs[i].logger);
			peers.push(peer);
		}

		peers
	}

	fn establish_connection<'a>(peer_a: &PeerManager<FileDescriptor, &'a test_utils::TestChannelMessageHandler, &'a test_utils::TestRoutingMessageHandler, &'a test_utils::TestLogger>, peer_b: &PeerManager<FileDescriptor, &'a test_utils::TestChannelMessageHandler, &'a test_utils::TestRoutingMessageHandler, &'a test_utils::TestLogger>) -> (FileDescriptor, FileDescriptor) {
		let secp_ctx = Secp256k1::new();
		let a_id = PublicKey::from_secret_key(&secp_ctx, &peer_a.inner.our_node_secret);
		let mut fd_a = FileDescriptor { fd: 1, outbound_data: Arc::new(Mutex::new(Vec::new())) };
		let mut fd_b = FileDescriptor { fd: 1, outbound_data: Arc::new(Mutex::new(Vec::new())) };
		let initial_data = peer_b.new_outbound_connection(a_id, fd_b.clone()).unwrap();
		peer_a.new_inbound_connection(fd_a.clone()).unwrap();
		assert_eq!(peer_a.read_event(&mut fd_a, &initial_data).unwrap(), false);
		assert_eq!(peer_b.read_event(&mut fd_b, &fd_a.outbound_data.lock().unwrap().split_off(0)).unwrap(), false);
		assert_eq!(peer_a.read_event(&mut fd_a, &fd_b.outbound_data.lock().unwrap().split_off(0)).unwrap(), false);
		(fd_a.clone(), fd_b.clone())
	}

	fn establish_connection_and_read_events<'a>(peer_a: &PeerManager<FileDescriptor, &'a test_utils::TestChannelMessageHandler, &'a test_utils::TestRoutingMessageHandler, &'a test_utils::TestLogger>, peer_b: &PeerManager<FileDescriptor, &'a test_utils::TestChannelMessageHandler, &'a test_utils::TestRoutingMessageHandler, &'a test_utils::TestLogger>) -> (FileDescriptor, FileDescriptor) {
		let (mut fd_a, mut fd_b) = establish_connection(peer_a, peer_b);
		assert_eq!(peer_b.read_event(&mut fd_b, &fd_a.outbound_data.lock().unwrap().split_off(0)).unwrap(), false);
		assert_eq!(peer_a.read_event(&mut fd_a, &fd_b.outbound_data.lock().unwrap().split_off(0)).unwrap(), false);
		(fd_a.clone(), fd_b.clone())
	}

	#[test]
	fn test_disconnect_peer() {
		// Simple test which builds a network of PeerManager, connects and brings them to NoiseState::Finished and
		// push a DisconnectPeer event to remove the node flagged by id
		let cfgs = create_peermgr_cfgs(2);
		let chan_handler = test_utils::TestChannelMessageHandler::new();
		let mut peers = create_network(2, &cfgs);
		establish_connection(&peers[0], &peers[1]);
		assert_eq!(peers[0].inner.peers.lock().unwrap().peers.len(), 1);

		let secp_ctx = Secp256k1::new();
		let their_id = PublicKey::from_secret_key(&secp_ctx, &peers[1].inner.our_node_secret);

		chan_handler.pending_events.lock().unwrap().push(events::MessageSendEvent::HandleError {
			node_id: their_id,
			action: msgs::ErrorAction::DisconnectPeer { msg: None },
		});
		assert_eq!(chan_handler.pending_events.lock().unwrap().len(), 1);
		peers[0].inner.message_handler.chan_handler = &chan_handler;

		peers[0].process_events();
		assert_eq!(peers[0].inner.peers.lock().unwrap().peers.len(), 0);
	}

	#[test]
	fn test_timer_tick_occurred() {
		// Create peers, a vector of two peer managers, perform initial set up and check that peers[0] has one Peer.
		let cfgs = create_peermgr_cfgs(2);
		let peers = create_network(2, &cfgs);
		establish_connection(&peers[0], &peers[1]);
		assert_eq!(peers[0].inner.peers.lock().unwrap().peers.len(), 1);

		// peers[0] awaiting_pong is set to true, but the Peer is still connected
		peers[0].timer_tick_occured();
		assert_eq!(peers[0].inner.peers.lock().unwrap().peers.len(), 1);

		// Since timer_tick_occured() is called again when awaiting_pong is true, all Peers are disconnected
		peers[0].timer_tick_occured();
		assert_eq!(peers[0].inner.peers.lock().unwrap().peers.len(), 0);
	}

	#[test]
	fn test_do_attempt_write_data() {
		// Create 2 peers with custom TestRoutingMessageHandlers and connect them.
		let cfgs = create_peermgr_cfgs(2);
		cfgs[0].routing_handler.request_full_sync.store(true, Ordering::Release);
		cfgs[1].routing_handler.request_full_sync.store(true, Ordering::Release);
		let peers = create_network(2, &cfgs);

		// By calling establish_connect, we trigger do_attempt_write_data between
		// the peers. Previously this function would mistakenly enter an infinite loop
		// when there were more channel messages available than could fit into a peer's
		// buffer. This issue would now be detected by this test (because we use custom
		// RoutingMessageHandlers that intentionally return more channel messages
		// than can fit into a peer's buffer).
		let (mut fd_a, mut fd_b) = establish_connection(&peers[0], &peers[1]);

		// Make each peer to read the messages that the other peer just wrote to them.
		peers[1].read_event(&mut fd_b, &fd_a.outbound_data.lock().unwrap().split_off(0)).unwrap();
		peers[0].read_event(&mut fd_a, &fd_b.outbound_data.lock().unwrap().split_off(0)).unwrap();

		// Check that each peer has received the expected number of channel updates and channel
		// announcements.
		assert_eq!(cfgs[0].routing_handler.chan_upds_recvd.load(Ordering::Acquire), 100);
		assert_eq!(cfgs[0].routing_handler.chan_anns_recvd.load(Ordering::Acquire), 50);
		assert_eq!(cfgs[1].routing_handler.chan_upds_recvd.load(Ordering::Acquire), 100);
		assert_eq!(cfgs[1].routing_handler.chan_anns_recvd.load(Ordering::Acquire), 50);
	}

	#[test]
	fn limit_initial_routing_sync_requests() {
		// Inbound peer 0 requests initial_routing_sync, but outbound peer 1 does not.
		{
			let cfgs = create_peermgr_cfgs(2);
			cfgs[0].routing_handler.request_full_sync.store(true, Ordering::Release);
			let peers = create_network(2, &cfgs);
			let (fd_0_to_1, fd_1_to_0) = establish_connection_and_read_events(&peers[0], &peers[1]);

			let peer_0 = peers[0].inner.peers.lock().unwrap();
			let peer_1 = peers[1].inner.peers.lock().unwrap();

			let peer_0_features = peer_1.peers.get(&fd_1_to_0).unwrap().their_features.as_ref();
			let peer_1_features = peer_0.peers.get(&fd_0_to_1).unwrap().their_features.as_ref();

			assert!(peer_0_features.unwrap().initial_routing_sync());
			assert!(!peer_1_features.unwrap().initial_routing_sync());
		}

		// Outbound peer 1 requests initial_routing_sync, but inbound peer 0 does not.
		{
			let cfgs = create_peermgr_cfgs(2);
			cfgs[1].routing_handler.request_full_sync.store(true, Ordering::Release);
			let peers = create_network(2, &cfgs);
			let (fd_0_to_1, fd_1_to_0) = establish_connection_and_read_events(&peers[0], &peers[1]);

			let peer_0 = peers[0].inner.peers.lock().unwrap();
			let peer_1 = peers[1].inner.peers.lock().unwrap();

			let peer_0_features = peer_1.peers.get(&fd_1_to_0).unwrap().their_features.as_ref();
			let peer_1_features = peer_0.peers.get(&fd_0_to_1).unwrap().their_features.as_ref();

			assert!(!peer_0_features.unwrap().initial_routing_sync());
			assert!(peer_1_features.unwrap().initial_routing_sync());
		}
	}
}
