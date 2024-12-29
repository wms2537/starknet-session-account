// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts for Cairo ^0.19.0



#[starknet::contract(account)]
pub mod NexAccount {
    use openzeppelin::account::AccountComponent;
    use openzeppelin::introspection::src5::SRC5Component;
    use openzeppelin::upgrades::interface::IUpgradeable;
    use openzeppelin::upgrades::UpgradeableComponent;
    use openzeppelin::security::ReentrancyGuardComponent;

    use contracts::components::session_key::session_key_component;
    use starknet::{
        account::Call,
        get_tx_info,
        get_execution_info,
        get_caller_address,
        get_contract_address,
        VALIDATED,
        ClassHash
    };
    use core::starknet::storage::{StoragePointerReadAccess, StoragePathEntry};
    use core::starknet::syscalls::call_contract_syscall;
    use core::array::SpanTrait;
    use core::traits::TryInto;
    use core::traits::Into;
    use core::num::traits::Zero;
    use core::ecdsa;
    use contracts::utils::asserts::assert_no_self_call;

    component!(path: AccountComponent, storage: account, event: AccountEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);
    component!(path: session_key_component, storage: session_key, event: SessionKeyEvent);
    component!(path: ReentrancyGuardComponent, storage: reentrancy_guard, event: ReentrancyGuardEvent);
    // Internal
    impl AccountInternalImpl = AccountComponent::InternalImpl<ContractState>;
    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;
    #[abi(embed_v0)]
    impl SessionImpl = session_key_component::SessionImpl<ContractState>;
    #[abi(embed_v0)]
    impl PermissionImpl = session_key_component::PermissionImpl<ContractState>;
    #[abi(embed_v0)]
    impl PolicyImpl = session_key_component::PolicyImpl<ContractState>;

    impl ReentrancyGuardInternalImpl = ReentrancyGuardComponent::InternalImpl<ContractState>;
    
    #[storage]
    struct Storage {
        #[substorage(v0)]
        account: AccountComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
        #[substorage(v0)]
        reentrancy_guard: ReentrancyGuardComponent::Storage,
        #[substorage(v0)]
        pub session_key: session_key_component::Storage
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        AccountEvent: AccountComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
        #[flat]
        ReentrancyGuardEvent: ReentrancyGuardComponent::Event,
        #[flat]
        SessionKeyEvent: session_key_component::Event,
    }

    mod Errors {
        pub const INVALID_SESSION_SIGNATURE: felt252 = 'Invalid session signature';
        pub const INVALID_CALLER: felt252 = 'Invalid caller';
        pub const INVALID_SELECTOR: felt252 = 'Invalid selector';
        pub const SESSION_EXPIRED: felt252 = 'Session expired';
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: felt252) {
        self.account.initializer(public_key);
    }

    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.account.assert_only_self();
            self.upgradeable.upgrade(new_class_hash);
        }
    }
    
    #[abi(per_item)]
    #[generate_trait]
    pub impl InternalImpl of InternalTrait {
        #[external(v0)]
        fn validate_session_transaction(
            ref self: ContractState,
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
            let session_entry = self.session_key.sessions.entry(session_public_key);
            let session_data = session_entry.data.read();
            
            // Verify that the public key matches the stored session
            assert(session_data.public_key == session_public_key, 'Invalid session key');

            // Check session validity last
            assert(!self.session_key.is_session_revoked(session_data.public_key), 'Session already revoked');
            
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
                            self.session_key.check_permission(
                                session_data.public_key, *call.to, *call.selector
                            ),
                            Errors::INVALID_SELECTOR
                        );
            
                        if (*call).calldata.len() >= 3 {
                            let amount_low: u128 = (*call.calldata[1]).try_into().unwrap();
                            let amount_high: u128 = (*call.calldata[2]).try_into().unwrap();
                            let amount = u256 { low: amount_low, high: amount_high };
                            assert(
                                self.session_key.check_policy(session_data.public_key, *call.to, amount),
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

    #[abi(embed_v0)]
    impl SessionValidateImpl of starknet::account::AccountContract<ContractState> {
        fn __validate__(
            ref self: ContractState,
            mut calls: Array<Call>
        ) -> felt252 {
            let tx_info = get_tx_info().unbox();
            assert(tx_info.paymaster_data.is_empty(), 'unsupported-paymaster');

            // Check if it's a session key signature
            if self.session_key.is_session(tx_info.signature) {  // Need at least 4 elements for session signature
                // Try to validate as session transaction
                return InternalImpl::validate_session_transaction(
                    ref self, 
                    calls.span(), 
                    tx_info.signature,
                    tx_info.transaction_hash
                );
            } else {
                // Use account component's validation directly
                let is_valid = self.account._is_valid_signature(
                    tx_info.transaction_hash,
                    tx_info.signature
                );
                assert(is_valid, 'Invalid orig signature');
            }
            
            VALIDATED
        }

        fn __validate_declare__(
            self: @ContractState,
            class_hash: felt252
        ) -> felt252 {
            let tx_info = get_tx_info().unbox();
            
            // Use account component's validation directly
            let is_valid = self.account._is_valid_signature(
                class_hash,  // For declare, we validate the class_hash
                tx_info.signature
            );
            assert(is_valid, 'Invalid signature');
            VALIDATED
        }

        fn __execute__(
            ref self: ContractState,
            mut calls: Array<Call>
        ) -> Array<Span<felt252>> {
            self.reentrancy_guard.start();
            let sender = get_caller_address();
            assert(sender.is_zero(), Errors::INVALID_CALLER);

            // Check tx version
            let execution_info = get_execution_info().unbox();
            let tx_info = execution_info.tx_info.unbox();
            let tx_version: u256 = tx_info.version.try_into().unwrap();
            let block_info = execution_info.block_info.unbox();
            assert!(tx_version >= 1_u256, "Invalid tx version");

            // Check if it's a session transaction
            if self.session_key.is_session(tx_info.signature) {
                let session_public_key: felt252 = *tx_info.signature[1];  // Keep public key in signature
                let session_entry = self.session_key.sessions.entry(session_public_key);
                let session_data = session_entry.data.read();

                assert(block_info.block_timestamp < session_data.expires_at, 'Session expired');
            }

            // If not a session transaction, execute normally
            let mut result = ArrayTrait::new();
            let mut calls = calls;
            loop {
                match calls.pop_front() {
                    Option::Some(call) => {
                        let response = call_contract_syscall(
                            call.to,
                            call.selector,
                            call.calldata
                        ).unwrap();
                        result.append(response);
                    },
                    Option::None => { break; }
                };
            };
            self.reentrancy_guard.end();
            result
        }
    }
}
