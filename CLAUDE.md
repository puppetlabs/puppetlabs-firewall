# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
bundle install                          # Install dependencies
bundle exec rake parallel_spec          # Run all unit tests (parallel)
bundle exec rake lint                   # Run puppet-lint
bundle exec rake lint_fix               # Auto-fix lint issues
bundle exec rake metadata_lint          # Validate metadata.json
bundle exec rake check                  # All pre-release checks

# Single test file
bundle exec rspec spec/unit/puppet/type/firewall_spec.rb
# Single test by line number
bundle exec rspec spec/unit/puppet/type/firewall_spec.rb:25
# Single test by description
bundle exec rspec spec/unit/puppet/provider/firewall/firewall_public_spec.rb -e "creates the resource"
```

Acceptance tests require Litmus-provisioned VMs:
```bash
bundle exec rake litmus:provision_list[default]
bundle exec rake litmus:install_module
bundle exec rake litmus:acceptance:parallel
```

Generate updated reference docs:
```bash
puppet strings generate --format markdown --out REFERENCE.md
```

## Architecture

This module manages Linux firewall rules (iptables/ip6tables) and chains. It migrated to the **Puppet Resource API** in v7.0.0 — a breaking change. Older code using the legacy type/provider pattern should not be used as a reference.

### Type / Provider split

- [lib/puppet/type/firewall.rb](lib/puppet/type/firewall.rb) — ~100+ attributes registered via `Puppet::ResourceApi.register_type`. Handles attribute validation, feature declarations, and title format enforcement (`/^\d+[[:graph:][:space:]]+$/`).
- [lib/puppet/type/firewallchain.rb](lib/puppet/type/firewallchain.rb) — Chain management; name format is `{chain}:{table}:{protocol}` (e.g. `INPUT:filter:IPv4`).
- [lib/puppet/provider/firewall/firewall.rb](lib/puppet/provider/firewall/firewall.rb) — Core CRUD implementation. Reads state by parsing `iptables-save` / `ip6tables-save` output; writes by invoking iptables commands. Contains global variables for iptables command paths, regex patterns, and attribute-to-flag maps.
- [lib/puppet/provider/firewallchain/firewallchain.rb](lib/puppet/provider/firewallchain/firewallchain.rb) — Manages chains and default policies; supports purging unmanaged rules.

### Rule ordering and identity

Rules are numbered 000–999 in their title (e.g. `"001 accept loopback"`). The number is embedded as an iptables comment (`-m comment --comment "001 accept loopback"`), which is how the provider matches existing rules back to Puppet resources during `get()`. Titles 9000–9999 are conventionally reserved for post-rules. The `firewall::pre` and `firewall::post` classes are a user-defined convention (not shipped by this module) for establishing safe defaults before and after custom rules.

### State management

There is no persistent Puppet state file. Every Puppet run calls `iptables-save` to parse the live kernel ruleset, diffs it against the catalog, then issues `iptables` commands. Persistence across reboots is OS-specific (RedHat: `iptables` service; Debian: `iptables-persistent`; Arch/Gentoo: their own mechanisms) and is handled by the OS-family manifests under [manifests/linux/](manifests/linux/).

### Attribute negation

Most attributes accept a `!` prefix for inversion (e.g. `source => '! 192.168.1.0/24'`). Array-valued attributes negate either the first value or all values. This negation is parsed and regenerated in the provider.

### Utility helpers

- [lib/puppet_x/puppetlabs/firewall/utility.rb](lib/puppet_x/puppetlabs/firewall/utility.rb) — `persist_iptables()` (OS-specific rule save), `host_to_ip()` (hostname/IP/CIDR normalization).
- [lib/puppet_x/puppetlabs/firewall/ipcidr.rb](lib/puppet_x/puppetlabs/firewall/ipcidr.rb) — IPv4/IPv6 address and CIDR parsing.

### Test suite layout

- `spec/unit/puppet/type/` — attribute validation for both resource types.
- `spec/unit/puppet/provider/firewall/` — split across multiple files: `firewall_public_spec.rb` (create/update/delete), `firewall_private_get_spec.rb` (iptables-save parsing), `firewall_private_set_spec.rb` (iptables command generation), `firewall_output_parsing_spec.rb`.
- `spec/unit/classes/` — manifest class instantiation per OS family.
- `spec/acceptance/` — Litmus-based end-to-end tests covering happy-path, IPv6, exceptions, chains, and purge behaviour.
- `spec/fixtures/iptables/conversion_hash.rb` and `spec/fixtures/ip6tables/conversion_hash.rb` — large fixture hashes mapping iptables-save lines to expected Puppet resource attributes; extend these when adding new attribute support.

## Key constraints

- Requires Puppet >= 8.0.0, < 9.0.0 and stdlib >= 9.0.0, < 10.0.0.
- The `provider` attribute from the pre-v7 API was renamed `protocol`; `action` was merged into `jump`. Avoid using old attribute names.
- IPv6 rules must use the `ip6tables` provider (`:IPv6` suffix in chain name or `protocol => IPv6`).

## Project Rules

- At the start of a coding session, review the repository structure and any relevant README or documentation files to understand the area you are working in.
- Always read the files relevant to the task before suggesting or making a change.
- Never merge a pull request.
- Never work directly on the main or master branch.
- Never push a branch without explicit instruction.
- Never delete a file without permission — this applies even after a blanket "yes to all".
- Never output, log, save, or hardcode security-sensitive values — this includes passwords, tokens, API keys, private keys, secrets, and credentials of any kind. Do not write them to files, include them in commit messages, or print them in responses.
