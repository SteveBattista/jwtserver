# JWT Server User Manager

A command-line tool for managing users in the JWT server's `users.txt` file with Argon2id password hashing.

## Overview

This tool provides a secure and convenient way to manage user accounts for the JWT authentication server. It handles password hashing with Argon2id (the industry standard) and maintains the user database that the JWT server reads for authentication.

## Features

- ✅ Add new users with secure Argon2id password hashing
- ✅ Remove existing users safely
- ✅ Update user passwords with re-hashing
- ✅ List all users with formatted output
- ✅ Verify user passwords for testing
- ✅ Comprehensive error handling and validation
- ✅ Safe file operations with atomic writes
- ✅ Custom file path support
- ✅ Unit tests for reliability
- ✅ Cross-platform compatibility

## Installation

Navigate to the user_manager directory and build:

```bash
cd user_manager
cargo build --release
```

For a release build (faster execution):

```bash
cargo build --release
# Binary will be in target/release/user_manager
```

## Usage

All commands are run from the `user_manager` directory using `cargo run --`.

### Add a new user

```bash
cargo run -- add admin admin
cargo run -- add user1 password1
```

### List all users

```bash
cargo run -- list
```

### Update user password

```bash
cargo run -- update admin newpassword
```

### Remove a user

```bash
cargo run -- remove user1
```

### Verify a password

```bash
cargo run -- verify admin admin
```

### Use custom users file

```bash
cargo run -- --file /path/to/custom/users.txt list
```

## Complete Example Workflow

```bash
# Start fresh - navigate to user_manager directory
cd user_manager

# Add some demo users
cargo run -- add admin admin
cargo run -- add alice wonderland
cargo run -- add bob secretpass

# List all users to see them
cargo run -- list

# Update admin password for security
cargo run -- update admin supersecretpassword

# Verify the new password works
cargo run -- verify admin supersecretpassword

# Remove a user that's no longer needed
cargo run -- remove bob

# Final user list
cargo run -- list
```

## Integration with JWT Server

This tool manages the same `users.txt` file that the JWT server reads for authentication. When you:

1. **Add/Update users** → They can immediately log in to the JWT server
2. **Remove users** → They can no longer authenticate
3. **Verify passwords** → Test what the JWT server will accept

The JWT server automatically reads the updated file, so changes take effect immediately without server restart.

## File Format

The tool manages a `users.txt` file with this format:

```text
# JWT Server Users File
# Format: username:argon2id_hash
username:$argon2id$v=19$m=65536,t=3,p=4$salt$hash
```

## Security Features

- **Argon2id algorithm** - Industry standard for password hashing (winner of Password Hashing Competition)
- **Unique salt generation** - Each password gets a cryptographically random salt
- **Configurable parameters** - Memory cost, time cost, and parallelism settings
- **Input validation** - Prevents malformed usernames and ensures data integrity
- **Atomic file operations** - Safe concurrent access and crash recovery
- **No plaintext storage** - Passwords are immediately hashed and original is discarded

### Argon2id Parameters

The tool uses secure defaults:

- **Memory cost**: 65536 KB (64 MB)
- **Time cost**: 3 iterations  
- **Parallelism**: 4 threads
- **Salt length**: 16 bytes (randomly generated)

## Error Handling

The tool provides clear error messages for common issues:

- **Duplicate users**: "User 'username' already exists. Use 'update' to change password."
- **Missing users**: "User 'username' not found. Use 'add' to create new user."
- **File permissions**: Clear messages about read/write access issues
- **Invalid formats**: Warnings about malformed lines in users.txt
- **Network issues**: When using remote file paths

## Development & Testing

Run the test suite:

```bash
cargo test
```

Run with verbose logging:

```bash
RUST_LOG=debug cargo run -- list
```

Build for release (optimized):

```bash
cargo build --release
# Binary: target/release/user_manager
```
