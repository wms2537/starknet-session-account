# NEX Account: Advanced Session Key Implementation for StarkNet

NEX Account is a powerful StarkNet account implementation that introduces secure and flexible session key management, enabling delegated transaction execution with granular permissions and policy controls.

## Features

### 🔑 Session Key Management
- Create time-bound session keys for delegated account access
- Revoke sessions at any time
- Validate sessions with secure ECDSA signatures
- Track session status with efficient caching

### 🛡️ Permission System
- Fine-grained permission control per contract and function
- Whitelist/Blacklist modes for function selectors
- Batch permission updates
- Per-session contract access controls

### 📊 Policy Controls
- Set spending limits per session
- Configure time-window based restrictions
- Track and limit transaction volumes
- Automatic policy resets based on time windows

### 🔒 Security Features
- OpenZeppelin-based secure account implementation
- Comprehensive signature validation
- Built-in timestamp validation
- Protection against session key misuse

## Installation

```bash
scarb add nex_account
```

## Quick Start

1. Deploy NEX Account:
```cairo
let account = NexAccount::constructor(owner_public_key);
```

2. Register a Session:
```cairo
// Create a session that expires in 24 hours
let session = Session {
    public_key: session_public_key,
    expires_at: get_block_timestamp() + 86400,
    metadata: ByteArray!("")
};
account.register_session(session, guid_or_address);
```

3. Set Permissions:
```cairo
// Whitelist specific functions for the session
account.set_permission(
    session_public_key,
    contract_address,
    AccessMode::Whitelist,
    array![transfer_selector, approve_selector]
);
```

4. Configure Policy:
```cairo
// Set spending limits
let policy = Policy {
    max_amount: u256 { low: 1000, high: 0 },
    current_amount: u256 { low: 0, high: 0 },
};
account.set_policy(session_public_key, contract_address, policy);
```

## Architecture

NEX Account uses a component-based architecture with:
- Session Key Component: Manages session lifecycle and validation
- Permission Component: Handles access control
- Policy Component: Enforces transaction limits and policies

## Security Considerations

- Session keys are time-bound and can be revoked
- Permissions are explicitly granted per contract and function
- Policy controls prevent excessive usage
- All operations are validated against the session's constraints
- Built on OpenZeppelin's secure account implementation

## Contributing

Contributions are welcome! Please check out our [Contributing Guide](CONTRIBUTING.md).

## License

MIT License - see [LICENSE](LICENSE) for details.
