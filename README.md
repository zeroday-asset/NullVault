# NullVault

Offline Android vault and authenticator. **Experimental preview: test data only. No security audit has been completed.**

## Preview 0.3.0

- Folder assignment and filtering; Bitwarden folder names and all login URLs retained on import.
- Installed app links (`androidapp://package.name`) launch the app directly; copy-password switches to the selected target.
- Website favicons are fetched directly from HTTPS site origins, with an off switch. Installed-app icons are local. Unsupported/missing icons show a placeholder.
- Per-entry GitHub repository URL and launch button.
- Searchable vault list with separate entry details, add/edit forms, and settings, using a Bitwarden-inspired arrangement and original NullVault branding.
- Passwords and authenticator codes hidden by default. Reveal and copy within an entry. Clipboard clearing after 30 seconds (when the app process is alive).
- Master-password derivation and vault writes run off the UI thread. Configurable background timeout (5 minutes by default), immediate screen-off/manual locking. Brief file-picker and app switches retain the session.
- AES-256-GCM authenticated encryption, random salt/nonce, PBKDF2-HMAC-SHA256 at 600,000 iterations. This implementation requires further independent review.
- Import unencrypted Aegis JSON (TOTP), unencrypted Bitwarden password-manager JSON (logins and notes), otpauth TOTP text, and encrypted NullVault backups.
- Import preview and exact-match duplicate detection; existing entries retained. Unsupported Bitwarden OTP fields and item types are preserved with an import notice; passwords and notes can still import. Original Bitwarden item metadata retained in encrypted backups; passkeys in that metadata are not usable credentials in this app.
- Export an encrypted portable NullVault backup through Android's file picker. Restore using the exporting vault's master password. Backup files contain no account-specific platform key.
- SHA-1/SHA-256/SHA-512 TOTP, 6–8 digits and configurable periods from imported data.

## Installation and signing

This build uses application ID `app.nullvault.preview3` and installs alongside the older alpha and 0.2 preview. Transfer entries with an encrypted export from the old preview and import into this build. The original APK used an ephemeral debug signing key that is not available to sign updates. Its data is left untouched. Preview debug signing is cached in Actions on a best-effort basis; cache eviction can still change the signing key. A durable private release signing configuration is required before real use. Do not uninstall a vault containing data you need.

## Not yet implemented

Encrypted Aegis/Bitwarden import, Google transfer QR, camera/image QR scanning, Nextcloud synchronization, attachments, Android autofill, active passkeys/FIDO support, sharing service, edit/delete history and security audit.

Aegis/Bitwarden plaintext exports contain secrets: handle them locally and remove unneeded copies after a verified import. Do not upload your real exports into GitHub or chat.

## Build and validation

GitHub Actions runs `gradle :app:testDebugUnitTest :app:assembleDebug` using Gradle 8.9 and JDK 17, and uploads the debug APK. Engine tests cover RFC 6238 vectors, authenticated-encryption round trips, incorrect keys, tampering, format imports, duplicate handling, and preserving the existing vault.

A successful build is not evidence of device behavior or a security audit.
