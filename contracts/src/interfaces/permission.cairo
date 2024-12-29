// SPDX-License-Identifier: MIT
use starknet::ContractAddress;

#[derive(Copy, Drop, Serde, PartialEq, starknet::Store)]
pub enum AccessMode {
    Whitelist,
    #[default]
    Blacklist
}

#[starknet::interface]
pub trait IPermission<TContractState> {
    fn set_permission(
        ref self: TContractState,
        public_key: felt252,
        contract: ContractAddress,
        mode: AccessMode,
        selectors: Array<felt252>
    );

    fn check_permission(
        self: @TContractState,
        public_key: felt252,
        contract: ContractAddress,
        selector: felt252
    ) -> bool;

    fn get_permission_details(
        self: @TContractState,
        public_key: felt252,
        contract: ContractAddress
    ) -> (AccessMode, Array<felt252>);
}
