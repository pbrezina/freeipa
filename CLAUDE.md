# FreeIPA S4U2Self X.509 Attestation — Development Context

## Branch: `s4u`

This branch implements S4U2Self X.509 attestation for FreeIPA — a protocol
that lets services (SSH, OIDC, MCP) obtain Kerberos tickets on behalf of
users by presenting short-lived X.509 certificates that attest to a
completed authentication event. The most recent work adds support for MCP
(Model Context Protocol) BOT ephemeral principals.

## Build Environment

The C code under `daemons/ipa-kdb/` only compiles within the full FreeIPA
build system (autotools + system krb5/LDAP/OpenSSL headers). LSP/clang
diagnostics like `'config.h' file not found`, `Unknown type name 'LDAP'`,
`Unknown type name 'krb5_context'` are expected noise — ignore them.

## Architecture Overview

### S4U2Self X.509 Flow

1. A service (SSH server, OIDC relying party, MCP server) authenticates a
   user through its own mechanism.
2. The service builds a short-lived X.509 attestation certificate containing:
   - Subject: the authenticated user's principal name
   - PKINIT SAN: the user's Kerberos principal (for KDC identification)
   - `id-ce-kerberosServiceIssuerBinding` extension: ties the cert to a
     specific host, service type, keytab key, with an HKDF-derived signature
   - Service-specific authentication context extension (SSH, OIDC, or MCP)
3. The service presents this cert via S4U2Self (PA-FOR-X509-USER) to the KDC.
4. The IPA KDB plugin (`ipa_kdb_s4u_x509.c`) validates the cert, checks the
   binding, and issues a Kerberos ticket for the user.

### Service Handler Table

The KDB plugin dispatches to per-service handlers via the `s4u_handlers[]`
table (`ipa_kdb_s4u_x509.c:~1090`). Each entry specifies:
- `service_type` — "ssh", "oidc", "mcp"
- `context_ext_oid` — OID of the service-specific cert extension
- `parse_context` / `free_context` — ASN.1 codec for the extension
- `verify_context` — service-specific validation logic

### Key OIDs (under 2.16.840.1.113730.3.8.15.3.*)

| OID suffix | Name | Purpose |
|---|---|---|
| .1 | `kerberosServiceIssuerBinding` | Host/keytab binding (all services) |
| .2 | `sshAuthnContext` | SSH auth method, session ID, fingerprint |
| .3 | `oidcAuthnContext` | OIDC issuer, token hash, AMR |
| .4 | `mcpAuthnContext` | MCP bot metadata, OAuth2 token |

## MCP BOT Ephemeral Principals

### Problem

AI agents (MCP servers) act on behalf of users. We need Kerberos identities
that represent "agent X acting as user Y" — distinct from the user's own
identity, auditable, and short-lived.

### Solution: BOT-\<uidNumber\>-\<random\>

The MCP S4U flow creates ephemeral BOT principals:

```
MCP server authenticates user "admin" via OAuth2
  → builds attestation cert with Subject CN = "admin"
  → requests S4U2Self for principal "admin"
  → KDC's MCP handler looks up admin's uidNumber (e.g. 987456321)
  → generates random suffix (8 hex chars)
  → switches principal to BOT-987456321-a1b2c3d4@REALM
  → KDC issues ticket for BOT principal using admin's KDB entry (keys, policy)
```

### Critical Data Flow Direction

The MCP server requests S4U for the **original user** (admin), NOT for the
BOT. The BOT principal is unknown to the MCP server — it's constructed
entirely on the KDC side by `mcp_s4u_verify_context()`. This is the opposite
of what you might initially assume.

Because both `hint_princ` (from S4U request) and cert Subject CN are "admin",
the standard `s4u_lookup_user_by_cn()` works correctly for MCP — no special
lookup path is needed.

### Principal Resolution in ipadb_get_principal

`ipa_kdb_principals.c` handles the reverse direction — when the KDC later
needs to look up a BOT principal (e.g. for TGS-REQ):

1. `ipadb_switch_bot_to_user()`: Detects `BOT-` prefix, extracts uidNumber
   (digits between "BOT-" and last "-"), does LDAP search
   `(uidNumber=<N>)` under `ipactx->accounts_base`, reads
   `krbPrincipalName`, returns the real user's principal.
2. `ipadb_get_principal()` looks up the real user in the KDB.
3. `ipadb_switch_user_to_bot()`: Copies the original BOT principal back
   into `entry->princ`, so the ticket is issued for the BOT identity but
   uses the real user's keys/policy.

### MCP Certificate Extension (McpAuthnContext)

```asn1
id-ce-mcpAuthnContext (OID .4) ::= SEQUENCE {
    version         INTEGER (0),
    originalUser    UTF8String,          -- "admin"
    requestId       UTF8String,          -- session/request ID
    agentName       [0] EXPLICIT UTF8String OPTIONAL,  -- "claude"
    agentModel      [1] EXPLICIT UTF8String OPTIONAL,  -- "opus"
    toolId          [2] EXPLICIT UTF8String OPTIONAL,   -- "rhel-mcp"
    oauth2Token     [3] EXPLICIT UTF8String OPTIONAL    -- raw OAuth2 token
}
```

The `oauth2Token` carries the raw token for IPA-side validation. It is NOT
emitted as an auth indicator (indicators are short labels, not data carriers).

### Auth Indicators (PoC)

MCP bot metadata is encoded as Kerberos auth indicators in the PAC
(`ipa_kdb_mspac_v9.c`). This is a PoC approach — production should use a
custom field in AD-IF-RELEVANT.

Format: `mcp-bot-<field>:<value>`
- `mcp-bot-user:admin`
- `mcp-bot-agent:claude`
- `mcp-bot-model:opus`
- `mcp-bot-tool:rhel-mcp`

### ipadb_s4u_data Fields for MCP

In `ipa_kdb.h`, `struct ipadb_s4u_data` has:
```c
char *mcp_original_user;
char *mcp_request_id;
char *mcp_agent_name;
char *mcp_agent_model;
char *mcp_tool_id;
char *mcp_oauth2_token;
```

All are freed in `ipadb_free_principal_e_data()` in `ipa_kdb_principals.c`.

## Python Side: ipalib/x509_attestation/

The `ipalib/x509_attestation/` package builds the attestation certificates
on the service (client) side. Submodules:

| Module | Purpose |
|---|---|
| `keytab.py` | Enumerate host keytab, select best AES entry |
| `crypto.py` | HKDF key derivation, binding signature, ephemeral keys |
| `asn1.py` | DER encoding of all extensions and PKINIT SAN |
| `cert.py` | X.509 certificate assembly |
| `gss.py` | GSSAPI S4U2Self / S4U2Proxy |

### Public Certificate Builders

- `build_attestation_cert()` — SSH-specific (backward compat)
- `build_oidc_attestation_cert()` — OIDC-specific
- `build_mcp_attestation_cert()` — MCP BOT attestation
- `build_service_attestation_cert()` — generic, any service type

All delegate to `_build_cert_core()` which handles the common X.509
structure, PKINIT SAN, issuer binding, and signing.

### DER Encoding (asn1.py)

Uses minimal hand-written DER helpers (`_tlv`, `_seq`, `_int_der`,
`_utf8str`, `_octstr`, `_genstr`, `_explicit`) to avoid version-specific
dependencies on `cryptography.hazmat.asn1`. All structures must be
byte-for-byte compatible with the C implementations in
`gss-s4u-x509-asn1.c` and `ipa_kdb_s4u_x509.c`.

## Commit History (recent, bottom = oldest)

```
e487b4b60 revert: remove hardcoded BOT principal PoC code
c7b960b7d poc: add MCP service handler for S4U X.509 BOT attestation
deee9892a poc: dynamic BOT-<uidNumber>-<random> principal resolution
ff7056e8d poc: encode MCP bot metadata as auth indicators
3e936f31b poc: add build_mcp_attestation_cert() Python shortcut
0bcc7fd0e poc: add OAuth2 token field to MCP attestation certificate
```

## Key Files

| File | What it does |
|---|---|
| `daemons/ipa-kdb/ipa_kdb_s4u_x509.c` | S4U X.509 attestation: ASN.1 structs, handler table, per-service verify callbacks |
| `daemons/ipa-kdb/ipa_kdb_principals.c` | `ipadb_get_principal()` with BOT-to-user and user-to-BOT switching |
| `daemons/ipa-kdb/ipa_kdb.h` | `struct ipadb_s4u_data` with MCP fields |
| `daemons/ipa-kdb/ipa_kdb_mspac_v9.c` | PAC issuance, auth indicator emission for MCP |
| `ipalib/x509_attestation/asn1.py` | Python DER encoding: OIDs, `encode_mcp_authn_context()` |
| `ipalib/x509_attestation/cert.py` | Python cert builder: `build_mcp_attestation_cert()` |
| `ipalib/x509_attestation/__init__.py` | Public API exports |

## Common Pitfalls

1. **Data flow direction**: The MCP server requests S4U for the ORIGINAL
   user, not the BOT. The KDB plugin constructs the BOT principal. Don't
   reverse this.

2. **uid vs uidNumber**: "uid" in `BOT-<uid>-<random>` means the POSIX
   `uidNumber` (integer like 987456321), NOT the LDAP `uid` attribute
   (username string like "admin").

3. **s4u_lookup_user_by_cn**: CAN and SHOULD be used for MCP. Both
   `hint_princ` and cert Subject CN are the original user (e.g. "admin"),
   so the standard CN-based lookup works.

4. **32-char username limit**: The username part (`BOT-<uidNumber>-<8hexchars>`)
   must fit within 32 characters (POSIX username limit). The `@REALM`
   suffix is not included in this limit.

5. **ASN.1 compatibility**: Python DER encoding in `asn1.py` must produce
   byte-for-byte identical output to the C code. When adding fields, update
   both sides and keep tag numbers synchronized.
