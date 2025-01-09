// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts for Cairo v0.20.0 (account/account.cairo)

use starknet::account::Call;
use starknet::ContractAddress;
use contracts::interfaces::session_key::{SessionData, SessionResult};
use contracts::interfaces::permission::{AccessMode, PermissionResult};
use contracts::interfaces::policy::{Policy};

#[starknet::interface]
pub trait AccountABI<TState> {
    // ISRC6
    fn __execute__(self: @TState, calls: Array<Call>) -> Array<Span<felt252>>;
    fn __validate__(ref self: TState, calls: Array<Call>) -> felt252;
    fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;

    // ISRC5
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;

    // IDeclarer
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;

    // IDeployable
    fn __validate_deploy__(
        self: @TState, class_hash: felt252, contract_address_salt: felt252, public_key: felt252,
    ) -> felt252;

    // IPublicKey
    fn get_public_key(self: @TState) -> felt252;
    fn set_public_key(ref self: TState, new_public_key: felt252, signature: Span<felt252>);

    // ISRC6CamelOnly
    fn isValidSignature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;

    // IPublicKeyCamel
    fn getPublicKey(self: @TState) -> felt252;
    fn setPublicKey(ref self: TState, newPublicKey: felt252, signature: Span<felt252>);

    // ISession
    fn register_session(ref self: TState, session: SessionData, guid_or_address: felt252);
    fn revoke_session(ref self: TState, public_key: felt252);
    fn is_session_registered(self: @TState, public_key: felt252, guid_or_address: felt252) -> bool;
    fn get_all_sessions(self: @TState) -> Array<felt252>;
    fn get_session(self: @TState, public_key: felt252) -> Option<SessionResult>;

    // IPermission
    fn set_permission(ref self: TState, public_key: felt252, contract: ContractAddress, mode: AccessMode, selectors: Array<felt252>);
    fn get_permission_details(self: @TState, public_key: felt252, contract: ContractAddress) -> PermissionResult;

    // IPolicy
    fn set_policy(ref self: TState, public_key: felt252, contract: ContractAddress, policy: Policy);
    fn get_policy(self: @TState, public_key: felt252, contract: ContractAddress) -> Option<Policy>;
}

/// # Account Component
///
/// The Account component enables contracts to behave as accounts.
#[starknet::component]
pub mod AccountComponent {
    use core::hash::{HashStateExTrait, HashStateTrait};
    use core::num::traits::Zero;
    use core::poseidon::PoseidonTrait;
    use openzeppelin::account::interface;
    use openzeppelin::account::utils::{execute_calls, is_tx_version_valid, is_valid_stark_signature};
    use openzeppelin::introspection::src5::SRC5Component;
    use openzeppelin::introspection::src5::SRC5Component::InternalTrait as SRC5InternalTrait;
    use openzeppelin::introspection::src5::SRC5Component::SRC5Impl;
    use starknet::account::Call;
    use starknet::{
        get_block_timestamp,
        get_execution_info,
        get_contract_address,
        get_tx_info,
        ContractAddress,
        VALIDATED,
    };
    use starknet::storage::{Map, Vec, StoragePointerReadAccess, StoragePointerWriteAccess, StoragePathEntry, VecTrait, MutableVecTrait};
    use contracts::interfaces::session_key::{Session, ISession, SessionData, SessionResult};
    use contracts::interfaces::permission::{AccessMode, IPermission, PermissionResult};
    use contracts::interfaces::policy::{Policy, IPolicy, PolicyResult};
    use contracts::utils::asserts::assert_no_self_call;
    use core::ecdsa;
    use super::AccountABI;


    #[storage]
    pub struct Storage {
        pub Account_public_key: felt252,
        pub sessions: Map<felt252, Session>,
        sessions_vec: Vec<felt252>,
        valid_session_cache: Map<(felt252, felt252), bool>,
    }

    #[event]
    #[derive(Drop, PartialEq, starknet::Event)]
    pub enum Event {
        OwnerAdded: OwnerAdded,
        OwnerRemoved: OwnerRemoved,
        SessionRegistered: SessionRegistered,
        SessionRevoked: SessionRevoked,
        PermissionUpdated: PermissionUpdated,
        PolicyUpdated: PolicyUpdated
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    pub struct OwnerAdded {
        #[key]
        pub new_owner_guid: felt252,
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    pub struct OwnerRemoved {
        #[key]
        pub removed_owner_guid: felt252,
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    struct SessionRegistered {
        public_key: felt252,
        guid_or_address: felt252
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    struct SessionRevoked {
        public_key: felt252
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    struct PermissionUpdated {
        public_key: felt252,
        contract: ContractAddress
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    struct PolicyUpdated {
        public_key: felt252,
        contract: ContractAddress
    }

    pub mod Errors {
        pub const INVALID_CALLER: felt252 = 'Account: invalid caller';
        pub const INVALID_SIGNATURE: felt252 = 'Account: invalid signature';
        pub const INVALID_TX_VERSION: felt252 = 'Account: invalid tx version';
        pub const UNAUTHORIZED: felt252 = 'Account: unauthorized';
        pub const INVALID_SESSION_SIGNATURE: felt252 = 'Invalid session signature';
        pub const INVALID_SELECTOR: felt252 = 'Invalid selector';
        pub const SESSION_EXPIRED: felt252 = 'Session expired';
    }

    #[starknet::interface]
    pub trait ISRC6<TState> {
        fn __execute__(self: @TState, calls: Array<Call>) -> Array<Span<felt252>>;
        fn __validate__(ref self: TState, calls: Array<Call>) -> felt252;
        fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    }

    //
    // External
    //

    #[embeddable_as(SRC6Impl)]
    impl SRC6<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of ISRC6<ComponentState<TContractState>> {
        /// Executes a list of calls from the account.
        ///
        /// Requirements:
        ///
        /// - The transaction version must be greater than or equal to `MIN_TRANSACTION_VERSION`.
        /// - If the transaction is a simulation (version >= `QUERY_OFFSET`), it must be
        /// greater than or equal to `QUERY_OFFSET` + `MIN_TRANSACTION_VERSION`.
        fn __execute__(
            self: @ComponentState<TContractState>, calls: Array<Call>,
        ) -> Array<Span<felt252>> {
            // Avoid calls from other contracts
            // https://github.com/OpenZeppelin/cairo-contracts/issues/344
            let sender = starknet::get_caller_address();
            assert(sender.is_zero(), Errors::INVALID_CALLER);
            assert(is_tx_version_valid(), Errors::INVALID_TX_VERSION);

            let execution_info = get_execution_info().unbox();
            let tx_info = execution_info.tx_info.unbox();
            let tx_version: u256 = tx_info.version.try_into().unwrap();
            let block_info = execution_info.block_info.unbox();
            assert!(tx_version >= 1_u256, "Invalid tx version");

            // Check if it's a session transaction
            if self.is_session(tx_info.signature) {
                let session_public_key: felt252 = *tx_info.signature[1];  // Keep public key in signature
                let session_entry = self.sessions.entry(session_public_key);
                let session_data = session_entry.data.read();

                assert(block_info.block_timestamp < session_data.expires_at, 'Session expired');
            }

            execute_calls(calls.span())
        }

        /// Verifies the validity of the signature for the current transaction.
        /// This function is used by the protocol to verify `invoke` transactions.
        fn __validate__(ref self: ComponentState<TContractState>, calls: Array<Call>) -> felt252 {
            let tx_info = get_tx_info().unbox();
            assert(tx_info.paymaster_data.is_empty(), 'unsupported-paymaster');

            // Check if it's a session key signature
            if self.is_session(tx_info.signature) {  // Need at least 4 elements for session signature
                // Try to validate as session transaction
                return self.validate_session_transaction( 
                    calls.span(), 
                    tx_info.signature,
                    tx_info.transaction_hash
                );
            }
            return self.validate_transaction();
            
        }

        /// Verifies that the given signature is valid for the given hash.
        fn is_valid_signature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            if self._is_valid_signature(hash, signature.span()) {
                starknet::VALIDATED
            } else {
                0
            }
        }
    }

    #[embeddable_as(DeclarerImpl)]
    impl Declarer<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of interface::IDeclarer<ComponentState<TContractState>> {
        /// Verifies the validity of the signature for the current transaction.
        /// This function is used by the protocol to verify `declare` transactions.
        fn __validate_declare__(
            self: @ComponentState<TContractState>, class_hash: felt252,
        ) -> felt252 {
            self.validate_transaction()
        }
    }

    #[embeddable_as(DeployableImpl)]
    impl Deployable<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of interface::IDeployable<ComponentState<TContractState>> {
        /// Verifies the validity of the signature for the current transaction.
        /// This function is used by the protocol to verify `deploy_account` transactions.
        fn __validate_deploy__(
            self: @ComponentState<TContractState>,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: felt252,
        ) -> felt252 {
            self.validate_transaction()
        }
    }

    #[embeddable_as(PublicKeyImpl)]
    impl PublicKey<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of interface::IPublicKey<ComponentState<TContractState>> {
        /// Returns the current public key of the account.
        fn get_public_key(self: @ComponentState<TContractState>) -> felt252 {
            self.Account_public_key.read()
        }

        /// Sets the public key of the account to `new_public_key`.
        ///
        /// Requirements:
        ///
        /// - The caller must be the contract itself.
        /// - The signature must be valid for the new owner.
        ///
        /// Emits both an `OwnerRemoved` and an `OwnerAdded` event.
        fn set_public_key(
            ref self: ComponentState<TContractState>,
            new_public_key: felt252,
            signature: Span<felt252>,
        ) {
            self.assert_only_self();

            let current_owner = self.Account_public_key.read();
            self.assert_valid_new_owner(current_owner, new_public_key, signature);

            self.emit(OwnerRemoved { removed_owner_guid: current_owner });
            self._set_public_key(new_public_key);
        }
    }

    /// Adds camelCase support for `ISRC6`.
    #[embeddable_as(SRC6CamelOnlyImpl)]
    impl SRC6CamelOnly<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of interface::ISRC6CamelOnly<ComponentState<TContractState>> {
        fn isValidSignature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            SRC6::is_valid_signature(self, hash, signature)
        }
    }

    /// Adds camelCase support for `PublicKeyTrait`.
    #[embeddable_as(PublicKeyCamelImpl)]
    impl PublicKeyCamel<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of interface::IPublicKeyCamel<ComponentState<TContractState>> {
        fn getPublicKey(self: @ComponentState<TContractState>) -> felt252 {
            self.Account_public_key.read()
        }

        fn setPublicKey(
            ref self: ComponentState<TContractState>,
            newPublicKey: felt252,
            signature: Span<felt252>,
        ) {
            PublicKey::set_public_key(ref self, newPublicKey, signature);
        }
    }

    #[embeddable_as(AccountMixinImpl)]
    impl AccountMixin<
        TContractState,
        +HasComponent<TContractState>,
        impl SRC5: SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of AccountABI<ComponentState<TContractState>> {
        // ISRC6
        fn __execute__(
            self: @ComponentState<TContractState>, calls: Array<Call>,
        ) -> Array<Span<felt252>> {
            SRC6::__execute__(self, calls)
        }

        fn __validate__(ref self: ComponentState<TContractState>, calls: Array<Call>) -> felt252 {
            SRC6::__validate__(ref self, calls)
        }

        fn is_valid_signature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            SRC6::is_valid_signature(self, hash, signature)
        }

        // ISRC6CamelOnly
        fn isValidSignature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            SRC6CamelOnly::isValidSignature(self, hash, signature)
        }

        // IDeclarer
        fn __validate_declare__(
            self: @ComponentState<TContractState>, class_hash: felt252,
        ) -> felt252 {
            Declarer::__validate_declare__(self, class_hash)
        }

        // IDeployable
        fn __validate_deploy__(
            self: @ComponentState<TContractState>,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: felt252,
        ) -> felt252 {
            Deployable::__validate_deploy__(self, class_hash, contract_address_salt, public_key)
        }

        // IPublicKey
        fn get_public_key(self: @ComponentState<TContractState>) -> felt252 {
            PublicKey::get_public_key(self)
        }

        fn set_public_key(
            ref self: ComponentState<TContractState>,
            new_public_key: felt252,
            signature: Span<felt252>,
        ) {
            PublicKey::set_public_key(ref self, new_public_key, signature);
        }

        // IPublicKeyCamel
        fn getPublicKey(self: @ComponentState<TContractState>) -> felt252 {
            PublicKeyCamel::getPublicKey(self)
        }

        fn setPublicKey(
            ref self: ComponentState<TContractState>,
            newPublicKey: felt252,
            signature: Span<felt252>,
        ) {
            PublicKeyCamel::setPublicKey(ref self, newPublicKey, signature);
        }

        // ISRC5
        fn supports_interface(
            self: @ComponentState<TContractState>, interface_id: felt252,
        ) -> bool {
            let src5 = get_dep_component!(self, SRC5);
            src5.supports_interface(interface_id)
        }

        // ISession
        fn register_session(
            ref self: ComponentState<TContractState>,
            session: SessionData,
            guid_or_address: felt252
        ) {
            SessionInternalImpl::register_session(ref self, session, guid_or_address);
        }

        fn revoke_session(
            ref self: ComponentState<TContractState>,
            public_key: felt252
        ) {
            SessionInternalImpl::revoke_session(ref self, public_key);
        }

        fn is_session_registered(
            self: @ComponentState<TContractState>,
            public_key: felt252,
            guid_or_address: felt252
        ) -> bool {
            SessionInternalImpl::is_session_registered(self, public_key, guid_or_address)
        }

        fn get_all_sessions(self: @ComponentState<TContractState>) -> Array<felt252> {
            SessionInternalImpl::get_all_sessions(self)
        }

        fn get_session(self: @ComponentState<TContractState>, public_key: felt252) -> Option<SessionResult> {
            SessionInternalImpl::get_session(self, public_key)
        }

        // IPermission
        fn set_permission(
            ref self: ComponentState<TContractState>,
            public_key: felt252,
            contract: ContractAddress,
            mode: AccessMode,
            selectors: Array<felt252>
        ) {
            PermissionInternalImpl::set_permission(ref self, public_key, contract, mode, selectors);
        }

        fn get_permission_details(
            self: @ComponentState<TContractState>,
            public_key: felt252,
            contract: ContractAddress
        ) -> PermissionResult {
            PermissionInternalImpl::get_permission_details(self, public_key, contract)
        }

        // IPolicy
        fn set_policy(
            ref self: ComponentState<TContractState>,
            public_key: felt252,
            contract: ContractAddress,
            policy: Policy
        ) {
            PolicyInternalImpl::set_policy(ref self, public_key, contract, policy);
        }

        fn get_policy(
            self: @ComponentState<TContractState>,
            public_key: felt252,
            contract: ContractAddress
        ) -> Option<Policy> {
            PolicyInternalImpl::get_policy(self, public_key, contract)
        }
    }

    #[embeddable_as(SessionImpl)]
    impl SessionInternalImpl<
        TContractState,
        +HasComponent<TContractState>
    > of ISession<ComponentState<TContractState>> {
        fn register_session(
            ref self: ComponentState<TContractState>,
            session: SessionData,
            guid_or_address: felt252
        ) {
            let public_key = session.public_key;
            assert(session.expires_at >= get_block_timestamp(), 'Session expired');

            self.sessions.entry(public_key).data.write(session);
            self.sessions_vec.append().write(public_key);
            self.valid_session_cache.entry((guid_or_address, public_key)).write(true);
            self.emit(SessionRegistered { public_key, guid_or_address });
        }

        fn revoke_session(
            ref self: ComponentState<TContractState>,
            public_key: felt252
        ) {
            let mut session_data = self.sessions.entry(public_key).data.read();
            assert(!session_data.is_revoked, 'Session already revoked');
            session_data.is_revoked = true;
            self.sessions.entry(public_key).data.write(session_data);
            self.emit(SessionRevoked { public_key });
        }

        fn is_session_revoked(
            self: @ComponentState<TContractState>,
            public_key: felt252
        ) -> bool {
            let session_data = self.sessions.entry(public_key).data.read();
            session_data.is_revoked
        }

        fn is_session(
            self: @ComponentState<TContractState>,
            signature: Span<felt252>
        ) -> bool {
            match signature.get(0) {
                Option::Some(session_magic) => *session_magic.unbox() == 'session-token',
                Option::None => false
            }
        }

        fn is_session_registered(
            self: @ComponentState<TContractState>,
            public_key: felt252,
            guid_or_address: felt252
        ) -> bool {
            if self.is_session_revoked(public_key) {
                return false;
            }
            self.valid_session_cache.entry((guid_or_address, public_key)).read()
        }

        fn get_all_sessions(
            self: @ComponentState<TContractState>
        ) -> Array<felt252> {
            let mut sessions: Array<felt252> = array![];
            for i in 0..self.sessions_vec.len() {
                sessions.append(self.sessions_vec.at(i).read());
            };
            sessions
        }

        fn get_session(
            self: @ComponentState<TContractState>,
            public_key: felt252
        ) -> Option<SessionResult> {
            let session_entry = self.sessions.entry(public_key);
            let session_data = session_entry.data.read();
            if session_data.public_key == 0 {
                Option::None
            } else {
                let mut permissions = array![];
                for i in 0..session_entry.permissions_vec.len() {
                    let contract = session_entry.permissions_vec.at(i).read();
                    let permission = session_entry.permissions_map.entry(contract);
                    let mut selectors = array![];
                    for j in 0..permission.selector_count.read() {
                        selectors.append(permission.selectors.entry(j).read());
                    };
                    permissions.append(PermissionResult {
                        mode: permission.mode.read(),
                        selectors: selectors,
                        contract: contract,
                    });
                };
                let mut policies = array![];
                for i in 0..session_entry.policies_vec.len() {
                    let contract = session_entry.policies_vec.at(i).read();
                    let policy = session_entry.policies_map.entry(contract);
                    policies.append(PolicyResult {
                        contract: contract,
                        max_amount: policy.max_amount.read(),
                        current_amount: policy.current_amount.read(),
                    });
                };
                Option::Some(SessionResult {
                    data: session_data,
                    permissions: permissions,
                    policies: policies,
                })
            }
        }
    }

    #[embeddable_as(PermissionImpl)]
    impl PermissionInternalImpl<
        TContractState,
        +HasComponent<TContractState>
    > of IPermission<ComponentState<TContractState>> {
        fn set_permission(
            ref self: ComponentState<TContractState>,
            public_key: felt252,
            contract: ContractAddress,
            mode: AccessMode,
            selectors: Array<felt252>
        ) {
            let session_entry = self.sessions.entry(public_key);
            let mut permission = session_entry.permissions_map.entry(contract);
            permission.mode.write(mode);


            let old_count = permission.selector_count.read();
            let mut i = 0;
            loop {
                if i >= old_count {
                    break;
                }
                permission.selectors_map.entry(permission.selectors.entry(i).read()).write(false);
                permission.selectors.entry(i).write(0);
                i += 1;
            };

            let mut new_count = 0;
            let mut selectors = selectors;
            loop {
                match selectors.pop_front() {
                    Option::Some(selector) => {
                        permission.selectors.entry(new_count).write(selector);
                        permission.selectors_map.entry(selector).write(true);
                        new_count += 1;
                    },
                    Option::None => { break; }
                };
            };
            permission.selector_count.write(new_count);
            session_entry.permissions_vec.append().write(contract);
            self.emit(PermissionUpdated { public_key, contract });
        }

        fn check_permission(
            self: @ComponentState<TContractState>,
            public_key: felt252,
            contract: ContractAddress,
            selector: felt252
        ) -> bool {
            let session_entry = self.sessions.entry(public_key);
            let permission = session_entry.permissions_map.entry(contract);
            let mode = permission.mode.read();
            let selector_exists = permission.selectors_map.entry(selector).read();
            
            match mode {
                AccessMode::Whitelist => selector_exists,
                AccessMode::Blacklist => !selector_exists,
            }
        }

        fn get_permission_details(
            self: @ComponentState<TContractState>,
            public_key: felt252,
            contract: ContractAddress
        ) -> PermissionResult {
            let session_entry = self.sessions.entry(public_key);
            let permission = session_entry.permissions_map.entry(contract);
            let mode = permission.mode.read();
            let count = permission.selector_count.read();
            
            let mut selectors = ArrayTrait::new();
            let mut i = 0;
            loop {
                if i >= count {
                    break;
                }
                let selector = permission.selectors.entry(i).read();
                selectors.append(selector);
                i += 1;
            };
            
            PermissionResult {
                mode: mode,
                selectors: selectors,
                contract: contract,
            }
        }
    }

    #[embeddable_as(PolicyImpl)]
    impl PolicyInternalImpl<
        TContractState,
        +HasComponent<TContractState>
    > of IPolicy<ComponentState<TContractState>> {
        fn set_policy(
            ref self: ComponentState<TContractState>,
            public_key: felt252,
            contract: ContractAddress,
            policy: Policy
        ) {
            let session_entry = self.sessions.entry(public_key);
            let mut policy = policy;
            session_entry.policies_map.entry(contract).write(policy);
            self.emit(PolicyUpdated { public_key, contract });
        }

        fn check_policy(
            ref self: ComponentState<TContractState>,
            public_key: felt252,
            contract: ContractAddress,
            amount: u256
        ) -> bool {
            let session_entry = self.sessions.entry(public_key);
            let mut policy = session_entry.policies_map.entry(contract).read();

            // Check if new amount would exceed limit
            let new_amount = policy.current_amount + amount;
            if new_amount > policy.max_amount {
                return false;
            }

            // Update policy state
            policy.current_amount = new_amount;
            session_entry.policies_map.entry(contract).write(policy);
            session_entry.policies_vec.append().write(contract);
            true
        }

        fn get_policy(
            self: @ComponentState<TContractState>,
            public_key: felt252,
            contract: ContractAddress
        ) -> Option<Policy> {
            let session_entry = self.sessions.entry(public_key);
            let policy = session_entry.policies_map.entry(contract).read();
            Option::Some(policy)
        }
    }

    //
    // Internal
    //

    #[generate_trait]
    pub impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        impl SRC5: SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of InternalTrait<TContractState> {
        /// Initializes the account with the given public key, and registers the ISRC6 interface ID.
        ///
        /// Emits an `OwnerAdded` event.
        fn initializer(ref self: ComponentState<TContractState>, public_key: felt252) {
            let mut src5_component = get_dep_component_mut!(ref self, SRC5);
            src5_component.register_interface(interface::ISRC6_ID);
            self._set_public_key(public_key);
        }

        /// Validates that the caller is the account itself. Otherwise it reverts.
        fn assert_only_self(self: @ComponentState<TContractState>) {
            let caller = starknet::get_caller_address();
            let self = starknet::get_contract_address();
            assert(self == caller, Errors::UNAUTHORIZED);
        }

        /// Validates that `new_owner` accepted the ownership of the contract.
        ///
        /// WARNING: This function assumes that `current_owner` is the current owner of the
        /// contract, and does not validate this assumption.
        ///
        /// Requirements:
        ///
        /// - The signature must be valid for the new owner.
        fn assert_valid_new_owner(
            self: @ComponentState<TContractState>,
            current_owner: felt252,
            new_owner: felt252,
            signature: Span<felt252>,
        ) {
            let message_hash = PoseidonTrait::new()
                .update_with('StarkNet Message')
                .update_with('accept_ownership')
                .update_with(starknet::get_contract_address())
                .update_with(current_owner)
                .finalize();

            let is_valid = is_valid_stark_signature(message_hash, new_owner, signature);
            assert(is_valid, Errors::INVALID_SIGNATURE);
        }

        /// Validates the signature for the current transaction.
        /// Returns the short string `VALID` if valid, otherwise it reverts.
        fn validate_transaction(self: @ComponentState<TContractState>) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            let tx_hash = tx_info.transaction_hash;
            let signature = tx_info.signature;
            assert(self._is_valid_signature(tx_hash, signature), Errors::INVALID_SIGNATURE);
            starknet::VALIDATED
        }

        /// Sets the public key without validating the caller.
        /// The usage of this method outside the `set_public_key` function is discouraged.
        ///
        /// Emits an `OwnerAdded` event.
        fn _set_public_key(ref self: ComponentState<TContractState>, new_public_key: felt252) {
            self.Account_public_key.write(new_public_key);
            self.emit(OwnerAdded { new_owner_guid: new_public_key });
        }

        /// Returns whether the given signature is valid for the given hash
        /// using the account's current public key.
        fn _is_valid_signature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Span<felt252>,
        ) -> bool {
            let public_key = self.Account_public_key.read();
            is_valid_stark_signature(hash, public_key, signature)
        }

        fn validate_session_transaction(
            ref self: ComponentState<TContractState>,
            calls: Span<Call>,
            mut signature: Span<felt252>,
            transaction_hash: felt252,
        ) -> felt252 {
            assert_no_self_call(calls, get_contract_address());
            // Verify signature format
            assert(signature.len() >= 4, 'Invalid signature length');  // magic + pubkey + r + s
            
            // Extract signature components
            let session_public_key = *signature[1];  // Keep public key in signature
            let sig_r = *signature[2];
            let sig_s = *signature[3];

            // Get transaction hash
            // Get session data from storage using public key from signature
            let session_entry = self.sessions.entry(session_public_key);
            let session_data = session_entry.data.read();
            
            // Verify that the public key matches the stored session
            assert(session_data.public_key == session_public_key, 'Invalid session key');

            // Check session validity last
            assert(!self.is_session_revoked(session_data.public_key), 'Session already revoked');
            
            // Verify signature
            assert(
                ecdsa::check_ecdsa_signature(
                    message_hash: transaction_hash,
                    public_key: session_public_key,
                    signature_r: sig_r,
                    signature_s: sig_s
                ),
                'Invalid session signature'
            );

            let mut calls = calls;
            loop {
                match calls.pop_front() {
                    Option::Some(call) => {
                        assert(
                            self.check_permission(
                                session_data.public_key, *call.to, *call.selector
                            ),
                            Errors::INVALID_SELECTOR
                        );
            
                        if (*call).calldata.len() >= 3 {
                            let amount_low: u128 = (*call.calldata[1]).try_into().unwrap();
                            let amount_high: u128 = (*call.calldata[2]).try_into().unwrap();
                            let amount = u256 { low: amount_low, high: amount_high };
                            assert(
                                self.check_policy(session_data.public_key, *call.to, amount),
                                'Policy check failed'
                            );
                        }
                    },
                    Option::None => { break; }
                };
            };

            VALIDATED
        }
    }
}
