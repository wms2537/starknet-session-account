// SPDX-License-Identifier: MIT

#[starknet::component]
pub mod session_key_component {
    use starknet::{
        get_block_timestamp,
        ContractAddress
    };
    use core::starknet::storage::{Map, Vec, StoragePointerReadAccess, StoragePointerWriteAccess, StoragePathEntry, VecTrait, MutableVecTrait};
    
    use contracts::interfaces::session_key::{Session, ISession};
    use contracts::interfaces::permission::{AccessMode, IPermission};
    use contracts::interfaces::policy::{Policy, IPolicy};

    #[storage]
    pub struct Storage {
        pub sessions: Map<felt252, Session>,
        sessions_vec: Vec<felt252>,
        valid_session_cache: Map<(felt252, felt252), bool>,
        permission_modes: Map<(felt252, ContractAddress), AccessMode>,
        permission_selector_count: Map<(felt252, ContractAddress), u32>,
        permission_selectors: Map<(felt252, ContractAddress, u32), felt252>,
        permission_active_selectors: Map<(felt252, ContractAddress, felt252), bool>,
        policies: Map<(felt252, ContractAddress), Policy>
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        SessionRegistered: SessionRegistered,
        SessionRevoked: SessionRevoked,
        PermissionUpdated: PermissionUpdated,
        PolicyUpdated: PolicyUpdated
    }

    #[derive(Drop, starknet::Event)]
    struct SessionRegistered {
        public_key: felt252,
        guid_or_address: felt252
    }

    #[derive(Drop, starknet::Event)]
    struct SessionRevoked {
        public_key: felt252
    }

    #[derive(Drop, starknet::Event)]
    struct PermissionUpdated {
        public_key: felt252,
        contract: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    struct PolicyUpdated {
        public_key: felt252,
        contract: ContractAddress
    }

    #[embeddable_as(SessionImpl)]
    impl SessionInternalImpl<
        TContractState,
        +HasComponent<TContractState>
    > of ISession<ComponentState<TContractState>> {
        fn register_session(
            ref self: ComponentState<TContractState>,
            session: Session,
            guid_or_address: felt252
        ) {
            let public_key = session.public_key;
            assert(session.expires_at >= get_block_timestamp(), 'Session expired');

            self.sessions.entry(public_key).write(session);
            self.sessions_vec.append().write(public_key);
            self.valid_session_cache.entry((guid_or_address, public_key)).write(true);
            self.emit(SessionRegistered { public_key, guid_or_address });
        }

        fn revoke_session(
            ref self: ComponentState<TContractState>,
            public_key: felt252
        ) {
            let mut session = self.sessions.entry(public_key).read();
            assert(!session.is_revoked, 'Session already revoked');
            session.is_revoked = true;
            self.sessions.entry(public_key).write(session);
            self.emit(SessionRevoked { public_key });
        }

        fn is_session_revoked(
            self: @ComponentState<TContractState>,
            public_key: felt252
        ) -> bool {
            let session = self.sessions.entry(public_key).read();
            session.is_revoked
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
        ) -> Option<Session> {
            let session = self.sessions.entry(public_key).read();
            if session.public_key == 0 {
                Option::None
            } else {
                Option::Some(session)
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
            self.permission_modes.entry((public_key, contract)).write(mode);

            let old_count = self.permission_selector_count.entry((public_key, contract)).read();
            let mut i = 0;
            loop {
                if i >= old_count {
                    break;
                }
                let old_selector = self.permission_selectors.entry((public_key, contract, i)).read();
                self.permission_active_selectors.entry((public_key, contract, old_selector)).write(false);
                i += 1;
            };

            let mut new_count = 0;
            let mut selectors = selectors;
            loop {
                match selectors.pop_front() {
                    Option::Some(selector) => {
                        self.permission_selectors.entry((public_key, contract, new_count)).write(selector);
                        self.permission_active_selectors.entry((public_key, contract, selector)).write(true);
                        new_count += 1;
                    },
                    Option::None => { break; }
                };
            };
            self.permission_selector_count.entry((public_key, contract)).write(new_count);

            self.emit(PermissionUpdated { public_key, contract });
        }

        fn check_permission(
            self: @ComponentState<TContractState>,
            public_key: felt252,
            contract: ContractAddress,
            selector: felt252
        ) -> bool {
            let mode = self.permission_modes.entry((public_key, contract)).read();
            let selector_exists = self.permission_active_selectors.entry((public_key, contract, selector)).read();
            
            match mode {
                AccessMode::Whitelist => selector_exists,
                AccessMode::Blacklist => !selector_exists,
            }
        }

        fn get_permission_details(
            self: @ComponentState<TContractState>,
            public_key: felt252,
            contract: ContractAddress
        ) -> (AccessMode, Array<felt252>) {
            let mode = self.permission_modes.entry((public_key, contract)).read();
            let count = self.permission_selector_count.entry((public_key, contract)).read();
            
            let mut selectors = ArrayTrait::new();
            let mut i = 0;
            loop {
                if i >= count {
                    break;
                }
                let selector = self.permission_selectors.entry((public_key, contract, i)).read();
                selectors.append(selector);
                i += 1;
            };
            
            (mode, selectors)
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
            let mut policy = policy;
            self.policies.entry((public_key, contract)).write(policy);
            self.emit(PolicyUpdated { public_key, contract });
        }

        fn check_policy(
            ref self: ComponentState<TContractState>,
            public_key: felt252,
            contract: ContractAddress,
            amount: u256
        ) -> bool {
            let mut policy = self.policies.entry((public_key, contract)).read();

            // Check if new amount would exceed limit
            let new_amount = policy.current_amount + amount;
            if new_amount > policy.max_amount {
                return false;
            }

            // Update policy state
            policy.current_amount = new_amount;
            self.policies.entry((public_key, contract)).write(policy);
            true
        }

        fn get_policy(
            self: @ComponentState<TContractState>,
            public_key: felt252,
            contract: ContractAddress
        ) -> Option<Policy> {
            let policy = self.policies.entry((public_key, contract)).read();
            Option::Some(policy)
        }
    }
}
