// SPDX-License-Identifier: MIT

#[starknet::component]
pub mod session_key_component {
    use starknet::{
        get_block_timestamp,
        ContractAddress
    };
    use core::starknet::storage::{Map, Vec, StoragePointerReadAccess, StoragePointerWriteAccess, StoragePathEntry, VecTrait, MutableVecTrait};
    
    use contracts::interfaces::session_key::{Session, ISession, SessionData, SessionResult};
    use contracts::interfaces::permission::{AccessMode, IPermission, PermissionResult};
    use contracts::interfaces::policy::{Policy, IPolicy, PolicyResult};

    #[storage]
    pub struct Storage {
        pub sessions: Map<felt252, Session>,
        sessions_vec: Vec<felt252>,
        valid_session_cache: Map<(felt252, felt252), bool>,
        // permission_modes: Map<(felt252, ContractAddress), AccessMode>,
        // permission_selector_count: Map<(felt252, ContractAddress), u32>,
        // permission_selectors: Map<(felt252, ContractAddress, u32), felt252>,
        // permission_active_selectors: Map<(felt252, ContractAddress, felt252), bool>,
        // policies: Map<(felt252, ContractAddress), Policy>
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
}
