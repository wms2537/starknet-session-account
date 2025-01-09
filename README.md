# Advanced Session Key Implementation for StarkNet

A StarkNet account implementation that introduces secure and flexible session key management, enabling delegated transaction execution with granular permissions and policy controls.

## Features

### 🔑 Session Key Management
- Create time-bound session keys for delegated account access
- Revoke sessions at any time
- Validate sessions with secure ECDSA signatures
- Track session status with efficient caching
- Support for metadata attachment to sessions
- Unique GUID/address association per session

### 🛡️ Permission System
- Fine-grained permission control per contract and function
- Whitelist/Blacklist modes for function selectors
- Batch permission updates
- Per-session contract access controls
- Selector-level granularity for function access

### 📊 Policy Controls
- Set spending limits per session
- Configure time-window based restrictions
- Track and limit transaction volumes
- Automatic policy resets based on time windows
- Per-contract policy enforcement
- Support for u256 amount tracking

### 🔒 Security Features
- OpenZeppelin-based secure account implementation
- Comprehensive signature validation (SRC-6 compliant)
- Built-in timestamp validation
- Protection against session key misuse
- Upgradeable contract architecture
- Event emission for all critical operations

