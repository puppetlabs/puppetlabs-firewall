<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](http://semver.org).

## [v8.1.7](https://github.com/puppetlabs/puppetlabs-firewall/tree/v8.1.7) - 2025-06-10

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v8.1.6...v8.1.7)

### Other

- (MODULES-11476) Fix non-idempotency of firewall table creation [#1263](https://github.com/puppetlabs/puppetlabs-firewall/pull/1263) ([shubhamshinde360](https://github.com/shubhamshinde360))

## [v8.1.6](https://github.com/puppetlabs/puppetlabs-firewall/tree/v8.1.6) - 2025-05-07

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v8.1.5...v8.1.6)

### Fixed

- Port ranges as string with hyphen as range indicator should work [#1212](https://github.com/puppetlabs/puppetlabs-firewall/pull/1212) ([2fa](https://github.com/2fa))

### Other

- (CAT-2296) Update github runner image to ubuntu-24.04 [#1259](https://github.com/puppetlabs/puppetlabs-firewall/pull/1259) ([shubhamshinde360](https://github.com/shubhamshinde360))

## [v8.1.5](https://github.com/puppetlabs/puppetlabs-firewall/tree/v8.1.5) - 2025-04-15

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v8.1.4...v8.1.5)

### Fixed

- Query gid to prevent errors with missing users with the same id (fixes #1229) [#1251](https://github.com/puppetlabs/puppetlabs-firewall/pull/1251) ([cmusik](https://github.com/cmusik))

## [v8.1.4](https://github.com/puppetlabs/puppetlabs-firewall/tree/v8.1.4) - 2025-02-26

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v8.1.3...v8.1.4)

### Fixed

- (CAT-2215) Update legacy facts [#1253](https://github.com/puppetlabs/puppetlabs-firewall/pull/1253) ([amitkarsale](https://github.com/amitkarsale))

## [v8.1.3](https://github.com/puppetlabs/puppetlabs-firewall/tree/v8.1.3) - 2024-12-05

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v8.1.2...v8.1.3)

### Fixed

- Prevent sources with zero prefix length being applied every agent run [#1189](https://github.com/puppetlabs/puppetlabs-firewall/pull/1189) ([nabertrand](https://github.com/nabertrand))

## [v8.1.2](https://github.com/puppetlabs/puppetlabs-firewall/tree/v8.1.2) - 2024-11-25

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v8.1.1...v8.1.2)

### Fixed

- (MODULE-11463): Fix rule parsing when iptables chains with '-A' in the name [#1210](https://github.com/puppetlabs/puppetlabs-firewall/pull/1210) ([2fa](https://github.com/2fa))
- Allow a singular numeric port for the `--to-ports` parameter [#1199](https://github.com/puppetlabs/puppetlabs-firewall/pull/1199) ([gcoxmoz](https://github.com/gcoxmoz))
- Add `tcp-reset` as an allowed option for `--reject-with` [#1194](https://github.com/puppetlabs/puppetlabs-firewall/pull/1194) ([gcoxmoz](https://github.com/gcoxmoz))

## [v8.1.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/v8.1.1) - 2024-10-28

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v8.1.0...v8.1.1)

### Added

- (CAT-2101) Add support for Debian-12 [#1236](https://github.com/puppetlabs/puppetlabs-firewall/pull/1236) ([skyamgarp](https://github.com/skyamgarp))

### Fixed

- (CAT-2088): Allow colon(:) in IP table syntax [#1240](https://github.com/puppetlabs/puppetlabs-firewall/pull/1240) ([span786](https://github.com/span786))

## [v8.1.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v8.1.0) - 2024-09-23

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v8.0.3...v8.1.0)

### Added

- Support ip[6]tables protocol in firewallchain [#1191](https://github.com/puppetlabs/puppetlabs-firewall/pull/1191) ([jcharaoui](https://github.com/jcharaoui))

## [v8.0.3](https://github.com/puppetlabs/puppetlabs-firewall/tree/v8.0.3) - 2024-07-19

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v8.0.2...v8.0.3)

### Fixed

- Fix resource generation ipcidr dependency [#1204](https://github.com/puppetlabs/puppetlabs-firewall/pull/1204) ([2fa](https://github.com/2fa))

## [v8.0.2](https://github.com/puppetlabs/puppetlabs-firewall/tree/v8.0.2) - 2024-05-22

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v8.0.1...v8.0.2)

### Fixed

- Fix "creation" of empty built-in firewall chains [#1206](https://github.com/puppetlabs/puppetlabs-firewall/pull/1206) ([2fa](https://github.com/2fa))

## [v8.0.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/v8.0.1) - 2024-03-20

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v8.0.0...v8.0.1)

### Fixed

- (MODULES-11449) - Fix for IPv6 NAT chain [#1201](https://github.com/puppetlabs/puppetlabs-firewall/pull/1201) ([Ramesh7](https://github.com/Ramesh7))

### Other

- fix typos in documentation [#1195](https://github.com/puppetlabs/puppetlabs-firewall/pull/1195) ([corporate-gadfly](https://github.com/corporate-gadfly))

## [v8.0.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v8.0.0) - 2024-02-08

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v7.0.2...v8.0.0)

### Changed

- [CAT-1425] : Removing RedHat/Scientific/OracleLinux 6 [#1163](https://github.com/puppetlabs/puppetlabs-firewall/pull/1163) ([rajat-puppet](https://github.com/rajat-puppet))

### Fixed

- (GH-1164) Only common jump values should be enforced as upcase [#1165](https://github.com/puppetlabs/puppetlabs-firewall/pull/1165) ([david22swan](https://github.com/david22swan))

## [v7.0.2](https://github.com/puppetlabs/puppetlabs-firewall/tree/v7.0.2) - 2023-09-14

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v7.0.1...v7.0.2)

### Fixed

- (GH-1158) Fix for `dport/sport/state/ctstate/ctstatus` comparisons [#1160](https://github.com/puppetlabs/puppetlabs-firewall/pull/1160) ([david22swan](https://github.com/david22swan))

## [v7.0.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/v7.0.1) - 2023-09-14

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v7.0.0...v7.0.1)

### Fixed

- (GH-1156) Fix for jump/goto attributes [#1157](https://github.com/puppetlabs/puppetlabs-firewall/pull/1157) ([david22swan](https://github.com/david22swan))

## [v7.0.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v7.0.0) - 2023-09-13

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v6.0.0...v7.0.0)

### Changed

- (CAT-376) Rework firewall module to use the resource_api [#1145](https://github.com/puppetlabs/puppetlabs-firewall/pull/1145) ([david22swan](https://github.com/david22swan))

### Fixed

- (maint) Update all README.md mentions of `action` to `jump` [#1151](https://github.com/puppetlabs/puppetlabs-firewall/pull/1151) ([david22swan](https://github.com/david22swan))
- (RUBOCOP) Resolve Rubocop Issues [#1149](https://github.com/puppetlabs/puppetlabs-firewall/pull/1149) ([david22swan](https://github.com/david22swan))

## [v6.0.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v6.0.0) - 2023-07-25

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v5.0.0...v6.0.0)

### Changed

- (CONT-242) Fix duplicate rule detection [#1140](https://github.com/puppetlabs/puppetlabs-firewall/pull/1140) ([david22swan](https://github.com/david22swan))
- pdksync - (MAINT) - Require Stdlib 9.x only [#1135](https://github.com/puppetlabs/puppetlabs-firewall/pull/1135) ([LukasAud](https://github.com/LukasAud))

### Added

- Add support for parsing and using --tcp-option [#1126](https://github.com/puppetlabs/puppetlabs-firewall/pull/1126) ([greatflyingsteve](https://github.com/greatflyingsteve))

### Fixed

- disable firewalld for RedHat 9 [#1142](https://github.com/puppetlabs/puppetlabs-firewall/pull/1142) ([robertc99](https://github.com/robertc99))
- Change ip6tables_version to constant in provider. [#1134](https://github.com/puppetlabs/puppetlabs-firewall/pull/1134) ([pjakubcz](https://github.com/pjakubcz))
- Fix SELinux context on newer CentOS [#1123](https://github.com/puppetlabs/puppetlabs-firewall/pull/1123) ([tobias-urdin](https://github.com/tobias-urdin))
- Force firewall chain delete [#1104](https://github.com/puppetlabs/puppetlabs-firewall/pull/1104) ([cruelsmith](https://github.com/cruelsmith))

## [v5.0.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v5.0.0) - 2023-03-31

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v4.1.0...v5.0.0)

### Changed

- (Cont 779) Add Support for Puppet 8 / Drop Support for Puppet 6 [#1118](https://github.com/puppetlabs/puppetlabs-firewall/pull/1118) ([david22swan](https://github.com/david22swan))

## [v4.1.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v4.1.0) - 2023-03-31

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v4.0.1...v4.1.0)

### Added

- (CONT-352) Syntax update [#1110](https://github.com/puppetlabs/puppetlabs-firewall/pull/1110) ([LukasAud](https://github.com/LukasAud))

### Fixed

- Ignore OpenBSD, similarly to FreeBSD [#1107](https://github.com/puppetlabs/puppetlabs-firewall/pull/1107) ([buzzdeee](https://github.com/buzzdeee))
- redhat9 needs iptables service [#1103](https://github.com/puppetlabs/puppetlabs-firewall/pull/1103) ([robertc99](https://github.com/robertc99))
- debian: service: fix `ensure` parameter usage [#1095](https://github.com/puppetlabs/puppetlabs-firewall/pull/1095) ([damonbreeden](https://github.com/damonbreeden))

## [v4.0.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/v4.0.1) - 2022-12-07

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v4.0.0...v4.0.1)

### Fixed

- (GH-1097) Bumping back required puppet version [#1098](https://github.com/puppetlabs/puppetlabs-firewall/pull/1098) ([LukasAud](https://github.com/LukasAud))
- support --nflog-size as replacement for --nflog-range [#1096](https://github.com/puppetlabs/puppetlabs-firewall/pull/1096) ([kjetilho](https://github.com/kjetilho))
- (1093) - Fix unresolved fact error [#1094](https://github.com/puppetlabs/puppetlabs-firewall/pull/1094) ([jordanbreen28](https://github.com/jordanbreen28))
- package "iptables" has been replaced by "iptables-nft" on EL9 [#1085](https://github.com/puppetlabs/puppetlabs-firewall/pull/1085) ([kjetilho](https://github.com/kjetilho))

## [v4.0.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v4.0.0) - 2022-11-22

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.6.0...v4.0.0)

### Changed

- (CONT-256) Removing outdated code [#1084](https://github.com/puppetlabs/puppetlabs-firewall/pull/1084) ([LukasAud](https://github.com/LukasAud))

### Added

- add support for using rpfilter in rules [#1059](https://github.com/puppetlabs/puppetlabs-firewall/pull/1059) ([cmusik](https://github.com/cmusik))

### Fixed

- (CONT-173) - Updating deprecated facter instances [#1079](https://github.com/puppetlabs/puppetlabs-firewall/pull/1079) ([jordanbreen28](https://github.com/jordanbreen28))
- pdksync - (CONT-189) Remove support for RedHat6 / OracleLinux6 / Scientific6 [#1078](https://github.com/puppetlabs/puppetlabs-firewall/pull/1078) ([david22swan](https://github.com/david22swan))
- pdksync - (CONT-130) - Dropping Support for Debian 9 [#1075](https://github.com/puppetlabs/puppetlabs-firewall/pull/1075) ([jordanbreen28](https://github.com/jordanbreen28))
- fix service port number lookup to use protocol [#1023](https://github.com/puppetlabs/puppetlabs-firewall/pull/1023) ([kjetilho](https://github.com/kjetilho))

## [v3.6.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.6.0) - 2022-10-03

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.5.0...v3.6.0)

### Added

- pdksync - (GH-cat-11) Certify Support for Ubuntu 22.04 [#1063](https://github.com/puppetlabs/puppetlabs-firewall/pull/1063) ([david22swan](https://github.com/david22swan))
- pdksync - (GH-cat-12) Add Support for Redhat 9 [#1054](https://github.com/puppetlabs/puppetlabs-firewall/pull/1054) ([david22swan](https://github.com/david22swan))

### Fixed

- allow persistence of firewall rules for Suse [#1061](https://github.com/puppetlabs/puppetlabs-firewall/pull/1061) ([corporate-gadfly](https://github.com/corporate-gadfly))
- (GH-1055) Fix for `--random-fully` [#1058](https://github.com/puppetlabs/puppetlabs-firewall/pull/1058) ([david22swan](https://github.com/david22swan))

## [v3.5.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.5.0) - 2022-05-17

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.4.0...v3.5.0)

### Added

- CentOS Stream 9 Support (should include RHEL9 when that releases) [#1028](https://github.com/puppetlabs/puppetlabs-firewall/pull/1028) ([tskirvin](https://github.com/tskirvin))

### Fixed

- pdksync - (GH-iac-334) Remove Support for Ubuntu 14.04/16.04 [#1038](https://github.com/puppetlabs/puppetlabs-firewall/pull/1038) ([david22swan](https://github.com/david22swan))
- Fix rpfilter parameter [#1013](https://github.com/puppetlabs/puppetlabs-firewall/pull/1013) ([onyxmaster](https://github.com/onyxmaster))

## [v3.4.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.4.0) - 2022-02-28

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.3.0...v3.4.0)

### Added

- (SEC-944) Handle duplicate system rules [#1030](https://github.com/puppetlabs/puppetlabs-firewall/pull/1030) ([chelnak](https://github.com/chelnak))

### Fixed

- pdksync - (IAC-1787) Remove Support for CentOS 6 [#1027](https://github.com/puppetlabs/puppetlabs-firewall/pull/1027) ([david22swan](https://github.com/david22swan))

## [v3.3.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.3.0) - 2021-12-15

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.2.0...v3.3.0)

### Added

- pdksync - (IAC-1753) - Add Support for AlmaLinux 8 [#1020](https://github.com/puppetlabs/puppetlabs-firewall/pull/1020) ([david22swan](https://github.com/david22swan))
- pdksync - (IAC-1751) - Add Support for Rocky 8 [#1017](https://github.com/puppetlabs/puppetlabs-firewall/pull/1017) ([david22swan](https://github.com/david22swan))

### Fixed

- Bugfix MODULES-11203: error on second apply when uid or gid is specified as a range [#1019](https://github.com/puppetlabs/puppetlabs-firewall/pull/1019) ([cmd-ntrf](https://github.com/cmd-ntrf))
- Fedora 34 and iptables-compat fix; properly utilising iptables param. [#1018](https://github.com/puppetlabs/puppetlabs-firewall/pull/1018) ([adamboutcher](https://github.com/adamboutcher))
- pdksync - (IAC-1598) - Remove Support for Debian 8 [#1015](https://github.com/puppetlabs/puppetlabs-firewall/pull/1015) ([david22swan](https://github.com/david22swan))
- Add carp protocol to :proto property [#1014](https://github.com/puppetlabs/puppetlabs-firewall/pull/1014) ([adrianiurca](https://github.com/adrianiurca))
- (MODULES-6876) lib/puppet/provider/firewall/iptables.rb - comments cleanup for parsing [#981](https://github.com/puppetlabs/puppetlabs-firewall/pull/981) ([tskirvin](https://github.com/tskirvin))

## [v3.2.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.2.0) - 2021-09-06

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.1.0...v3.2.0)

### Added

- pdksync - (IAC-1709) - Add Support for Debian 11 [#1005](https://github.com/puppetlabs/puppetlabs-firewall/pull/1005) ([david22swan](https://github.com/david22swan))

### Fixed

- Fix "undefined method `gsub' for nil:NilClass" when changing existing rule UID from absent to any present [#1010](https://github.com/puppetlabs/puppetlabs-firewall/pull/1010) ([onyxmaster](https://github.com/onyxmaster))

## [v3.1.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.1.0) - 2021-07-26

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.0.2...v3.1.0)

### Added

- add compatibility with Rocky Linux [#998](https://github.com/puppetlabs/puppetlabs-firewall/pull/998) ([vchepkov](https://github.com/vchepkov))

### Fixed

- (MODULES-11138) - Fix mac_source Facter.fact().value() issue with Facter 3 [#1002](https://github.com/puppetlabs/puppetlabs-firewall/pull/1002) ([adrianiurca](https://github.com/adrianiurca))

## [v3.0.2](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.0.2) - 2021-07-19

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.0.1...v3.0.2)

### Fixed

- sles-15: mac_source is downcased by iptables [#997](https://github.com/puppetlabs/puppetlabs-firewall/pull/997) ([adrianiurca](https://github.com/adrianiurca))
- fix: parsing random_fully in ip6tables [#996](https://github.com/puppetlabs/puppetlabs-firewall/pull/996) ([scoiatael](https://github.com/scoiatael))

## [v3.0.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.0.1) - 2021-06-21

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.0.0...v3.0.1)

### Fixed

- Fixed link to REFERENCE.md [#993](https://github.com/puppetlabs/puppetlabs-firewall/pull/993) ([Samgarr](https://github.com/Samgarr))
- Update README.md [#986](https://github.com/puppetlabs/puppetlabs-firewall/pull/986) ([arjenz](https://github.com/arjenz))

## [v3.0.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.0.0) - 2021-03-01

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.8.1...v3.0.0)

### Changed

- pdksync - (MAINT) Remove SLES 11 support [#977](https://github.com/puppetlabs/puppetlabs-firewall/pull/977) ([sanfrancrisko](https://github.com/sanfrancrisko))
- pdksync - (MAINT) Remove RHEL 5 family support [#976](https://github.com/puppetlabs/puppetlabs-firewall/pull/976) ([sanfrancrisko](https://github.com/sanfrancrisko))
- pdksync - Remove Puppet 5 from testing and bump minimal version to 6.0.0 [#972](https://github.com/puppetlabs/puppetlabs-firewall/pull/972) ([carabasdaniel](https://github.com/carabasdaniel))

## [v2.8.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.8.1) - 2021-02-09

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.8.0...v2.8.1)

### Fixed

- [MODULES-10907] Do not remove spaces from hex string with ! [#967](https://github.com/puppetlabs/puppetlabs-firewall/pull/967) ([adrianiurca](https://github.com/adrianiurca))

## [v2.8.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.8.0) - 2020-12-14

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.7.0...v2.8.0)

### Added

- pdksync - (feat) - Add support for Puppet 7 [#959](https://github.com/puppetlabs/puppetlabs-firewall/pull/959) ([daianamezdrea](https://github.com/daianamezdrea))
- (IAC-966) - MODULES-10522: Add support for the --condition parameter [#941](https://github.com/puppetlabs/puppetlabs-firewall/pull/941) ([adrianiurca](https://github.com/adrianiurca))

### Fixed

- Restore copyright names [#951](https://github.com/puppetlabs/puppetlabs-firewall/pull/951) ([hunner](https://github.com/hunner))

## [v2.7.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.7.0) - 2020-10-15

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.6.0...v2.7.0)

### Added

- (IAC-1190) add `ignore_foreign` when purging firewallchains [#948](https://github.com/puppetlabs/puppetlabs-firewall/pull/948) ([DavidS](https://github.com/DavidS))

## [v2.6.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.6.0) - 2020-10-05

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.5.0...v2.6.0)

### Added

- pdksync - (IAC-973) - Update travis/appveyor to run on new default branch main [#933](https://github.com/puppetlabs/puppetlabs-firewall/pull/933) ([david22swan](https://github.com/david22swan))

### Fixed

- Add carp protocol to :proto property [#945](https://github.com/puppetlabs/puppetlabs-firewall/pull/945) ([pellisesol](https://github.com/pellisesol))
- Fix extra quotes in firewall string matching [#944](https://github.com/puppetlabs/puppetlabs-firewall/pull/944) ([IBBoard](https://github.com/IBBoard))
- (IAC-987) - Removal of inappropriate terminology [#942](https://github.com/puppetlabs/puppetlabs-firewall/pull/942) ([david22swan](https://github.com/david22swan))

## [v2.5.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.5.0) - 2020-07-28

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.4.0...v2.5.0)

### Added

- Add acceptance and unit test [#931](https://github.com/puppetlabs/puppetlabs-firewall/pull/931) ([adrianiurca](https://github.com/adrianiurca))
- [IAC-899] - Add acceptance test for string_hex parameter [#930](https://github.com/puppetlabs/puppetlabs-firewall/pull/930) ([adrianiurca](https://github.com/adrianiurca))
- Add support for NFLOG options to ip6tables [#921](https://github.com/puppetlabs/puppetlabs-firewall/pull/921) ([frh](https://github.com/frh))

## [v2.4.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.4.0) - 2020-05-13

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.3.0...v2.4.0)

### Added

- Add support for u32 module in iptables [#917](https://github.com/puppetlabs/puppetlabs-firewall/pull/917) ([sanfrancrisko](https://github.com/sanfrancrisko))
- Add support for cgroup arg [#916](https://github.com/puppetlabs/puppetlabs-firewall/pull/916) ([akerl-unpriv](https://github.com/akerl-unpriv))
- Extend LOG options [#914](https://github.com/puppetlabs/puppetlabs-firewall/pull/914) ([martialblog](https://github.com/martialblog))

### Fixed

- (MODULES-8543) Remove nftables' backend warning from iptables_save outtput [#911](https://github.com/puppetlabs/puppetlabs-firewall/pull/911) ([NITEMAN](https://github.com/NITEMAN))

## [v2.3.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.3.0) - 2020-03-26

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.2.0...v2.3.0)

### Added

- Add iptables --hex-string support to firewall resource [#907](https://github.com/puppetlabs/puppetlabs-firewall/pull/907) ([alexconrey](https://github.com/alexconrey))
- Add random_fully and rpfilter support [#892](https://github.com/puppetlabs/puppetlabs-firewall/pull/892) ([treydock](https://github.com/treydock))
- (MODULES-7800) Add the ability to specify iptables connection tracking helpers. [#890](https://github.com/puppetlabs/puppetlabs-firewall/pull/890) ([jimmyt86](https://github.com/jimmyt86))
- Support conntrack module [#872](https://github.com/puppetlabs/puppetlabs-firewall/pull/872) ([haught](https://github.com/haught))

### Fixed

- (maint) Use fact.flush only when available [#906](https://github.com/puppetlabs/puppetlabs-firewall/pull/906) ([Filipovici-Andrei](https://github.com/Filipovici-Andrei))
- (MODULES-10358) - Clarification added to Boolean validation checks [#886](https://github.com/puppetlabs/puppetlabs-firewall/pull/886) ([david22swan](https://github.com/david22swan))
- Merge and remove duplicate README file, lint code snippets [#878](https://github.com/puppetlabs/puppetlabs-firewall/pull/878) ([runejuhl](https://github.com/runejuhl))

## [v2.2.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.2.0) - 2019-12-09

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.1.0...v2.2.0)

### Added

- Add support for Debian Unstable [#876](https://github.com/puppetlabs/puppetlabs-firewall/pull/876) ([martialblog](https://github.com/martialblog))
- (FM-8673) - Support added for CentOS 8 [#873](https://github.com/puppetlabs/puppetlabs-firewall/pull/873) ([david22swan](https://github.com/david22swan))
- FM-8400 - add debian10 support [#862](https://github.com/puppetlabs/puppetlabs-firewall/pull/862) ([lionce](https://github.com/lionce))
- FM-8219 - Convert to litmus [#855](https://github.com/puppetlabs/puppetlabs-firewall/pull/855) ([lionce](https://github.com/lionce))

### Fixed

- Change - Avoid puppet failures on windows nodes [#874](https://github.com/puppetlabs/puppetlabs-firewall/pull/874) ([blackknight36](https://github.com/blackknight36))
- Fix parsing iptables rules with hyphen in comments [#861](https://github.com/puppetlabs/puppetlabs-firewall/pull/861) ([Hexta](https://github.com/Hexta))

## [v2.1.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.1.0) - 2019-09-25

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.0.0...v2.1.0)

### Added

- (MODULES-6136) Add zone property of CT target. [#852](https://github.com/puppetlabs/puppetlabs-firewall/pull/852) ([rwf14f](https://github.com/rwf14f))
- (FM-8025) Add RedHat 8 support [#847](https://github.com/puppetlabs/puppetlabs-firewall/pull/847) ([eimlav](https://github.com/eimlav))

### Fixed

- MODULES-9801 - fix negated physdev [#858](https://github.com/puppetlabs/puppetlabs-firewall/pull/858) ([lionce](https://github.com/lionce))

## [v2.0.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.0.0) - 2019-05-15

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.15.3...v2.0.0)

### Changed

- pdksync - (MODULES-8444) - Raise lower Puppet bound [#841](https://github.com/puppetlabs/puppetlabs-firewall/pull/841) ([david22swan](https://github.com/david22swan))

### Added

- (FM-7903) - Implement Puppet Strings [#838](https://github.com/puppetlabs/puppetlabs-firewall/pull/838) ([david22swan](https://github.com/david22swan))

### Fixed

- (MODULES-8736) IPtables support on RHEL8 [#824](https://github.com/puppetlabs/puppetlabs-firewall/pull/824) ([EmilienM](https://github.com/EmilienM))

## [1.15.3](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.15.3) - 2019-04-05

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.15.2...1.15.3)

### Fixed

- (MODULES-8855) Move ipvs test to exception spec [#834](https://github.com/puppetlabs/puppetlabs-firewall/pull/834) ([eimlav](https://github.com/eimlav))
- (MODULES-8842) Fix ipvs not idempotent [#833](https://github.com/puppetlabs/puppetlabs-firewall/pull/833) ([eimlav](https://github.com/eimlav))

## [1.15.2](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.15.2) - 2019-03-26

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.15.1...1.15.2)

### Fixed

- (MODULES-8615) Fix rules with ipvs not parsing [#828](https://github.com/puppetlabs/puppetlabs-firewall/pull/828) ([eimlav](https://github.com/eimlav))
- (MODULES-7333) - Change hashing method from MD5 to SHA256 [#827](https://github.com/puppetlabs/puppetlabs-firewall/pull/827) ([david22swan](https://github.com/david22swan))
- (MODULES-6547) Fix existing rules with --dport not parsing [#826](https://github.com/puppetlabs/puppetlabs-firewall/pull/826) ([eimlav](https://github.com/eimlav))
- (MODULES-8648) - Fix for failures on SLES 11 [#816](https://github.com/puppetlabs/puppetlabs-firewall/pull/816) ([david22swan](https://github.com/david22swan))
- (MODULES-8584) Handle multiple escaped quotes in comments properly [#815](https://github.com/puppetlabs/puppetlabs-firewall/pull/815) ([mateusz-gozdek-sociomantic](https://github.com/mateusz-gozdek-sociomantic))
- External control for iptables-persistent [#795](https://github.com/puppetlabs/puppetlabs-firewall/pull/795) ([identw](https://github.com/identw))

## [1.15.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.15.1) - 2019-02-01

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.15.0...1.15.1)

### Fixed

- (DOC-3056) Remove mention of rules ordering [#809](https://github.com/puppetlabs/puppetlabs-firewall/pull/809) ([clairecadman](https://github.com/clairecadman))
- (FM-7712) - Remove Gentoo 1.0 testing/support for Firewall module [#808](https://github.com/puppetlabs/puppetlabs-firewall/pull/808) ([david22swan](https://github.com/david22swan))
- (MODULES-8360) Fix IPv6 bug relating to Bugzilla 1015 [#804](https://github.com/puppetlabs/puppetlabs-firewall/pull/804) ([alex-harvey-z3q](https://github.com/alex-harvey-z3q))

## [1.15.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.15.0) - 2019-01-18

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.14.0...1.15.0)

### Added

- (MODULES-8143) - Add SLES 15 support [#798](https://github.com/puppetlabs/puppetlabs-firewall/pull/798) ([eimlav](https://github.com/eimlav))
- Add nftables wrapper support for RHEL8 [#794](https://github.com/puppetlabs/puppetlabs-firewall/pull/794) ([mwhahaha](https://github.com/mwhahaha))
- Changed regex for iniface and outiface to allow '@' in interface names [#791](https://github.com/puppetlabs/puppetlabs-firewall/pull/791) ([GeorgeCox](https://github.com/GeorgeCox))
- (MODULES-8214) Handle src_type and dst_type as array [#790](https://github.com/puppetlabs/puppetlabs-firewall/pull/790) ([mateusz-gozdek-sociomantic](https://github.com/mateusz-gozdek-sociomantic))
- (MODULES-7990) Merge multiple comments into one while parsing rules [#789](https://github.com/puppetlabs/puppetlabs-firewall/pull/789) ([mateusz-gozdek-sociomantic](https://github.com/mateusz-gozdek-sociomantic))
- add -g flag handling in ip6tables.rb provider [#788](https://github.com/puppetlabs/puppetlabs-firewall/pull/788) ([cestith](https://github.com/cestith))
- (MODULES-7681) Add support for bytecode property [#771](https://github.com/puppetlabs/puppetlabs-firewall/pull/771) ([baurmatt](https://github.com/baurmatt))

### Fixed

- pdksync - (FM-7655) Fix rubygems-update for ruby < 2.3 [#801](https://github.com/puppetlabs/puppetlabs-firewall/pull/801) ([tphoney](https://github.com/tphoney))
- (MODULES-6340) - Address failure when name begins with 9XXX [#796](https://github.com/puppetlabs/puppetlabs-firewall/pull/796) ([eimlav](https://github.com/eimlav))
- Amazon linux 2 changed its major version to 2 with the last update... [#793](https://github.com/puppetlabs/puppetlabs-firewall/pull/793) ([erik-frontify](https://github.com/erik-frontify))

## [1.14.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.14.0) - 2018-09-27

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.13.0...1.14.0)

### Added

- pdksync - (MODULES-6805) metadata.json shows support for puppet 6 [#782](https://github.com/puppetlabs/puppetlabs-firewall/pull/782) ([tphoney](https://github.com/tphoney))
- (FM-7399) - Prepare for changelog generator [#780](https://github.com/puppetlabs/puppetlabs-firewall/pull/780) ([pmcmaw](https://github.com/pmcmaw))

## [1.13.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.13.0) - 2018-09-19

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.12.0...1.13.0)

### Added

- pdksync - (MODULES-7705) - Bumping stdlib dependency from < 5.0.0 to < 6.0.0 [#775](https://github.com/puppetlabs/puppetlabs-firewall/pull/775) ([pmcmaw](https://github.com/pmcmaw))
- Add support for Amazon Linux 2 [#768](https://github.com/puppetlabs/puppetlabs-firewall/pull/768) ([erik-frontify](https://github.com/erik-frontify))
- (FM-7232) - Update firewall to support Ubuntu 18.04 [#767](https://github.com/puppetlabs/puppetlabs-firewall/pull/767) ([david22swan](https://github.com/david22swan))
- [FM-7044] Addition of Debian 9 support to firewall [#765](https://github.com/puppetlabs/puppetlabs-firewall/pull/765) ([david22swan](https://github.com/david22swan))
- [FM-6961] Removal of unsupported OS from firewall [#764](https://github.com/puppetlabs/puppetlabs-firewall/pull/764) ([david22swan](https://github.com/david22swan))

### Fixed

- (MODULES-7627) - Update README Limitations section [#769](https://github.com/puppetlabs/puppetlabs-firewall/pull/769) ([eimlav](https://github.com/eimlav))
- Corrections to readme [#766](https://github.com/puppetlabs/puppetlabs-firewall/pull/766) ([alex-harvey-z3q](https://github.com/alex-harvey-z3q))
- (MODULES-6129) negated option with address mask bugfix [#756](https://github.com/puppetlabs/puppetlabs-firewall/pull/756) ([mirekys](https://github.com/mirekys))
- (MODULES-2119) iptables delete -p all exception [#749](https://github.com/puppetlabs/puppetlabs-firewall/pull/749) ([mikkergimenez](https://github.com/mikkergimenez))

## [1.12.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.12.0) - 2018-01-25

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.11.0...1.12.0)

### Fixed

- MODULES-6261: Fix error parsing rules with dashes in the chain name [#744](https://github.com/puppetlabs/puppetlabs-firewall/pull/744) ([hantona](https://github.com/hantona))
- (MODULES-6092) Set correct seluser for CentOS/RHEL 5.x [#737](https://github.com/puppetlabs/puppetlabs-firewall/pull/737) ([mihall-primus](https://github.com/mihall-primus))

## [1.11.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.11.0) - 2017-11-30

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.10.0...1.11.0)

### Fixed

- (MODULES-6029) Skip unparsable rules with warning [#738](https://github.com/puppetlabs/puppetlabs-firewall/pull/738) ([jistr](https://github.com/jistr))

## [1.10.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.10.0) - 2017-11-14

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.9.0...1.10.0)

### Changed

- (MODULES-5501) - Remove unsupported Ubuntu [#715](https://github.com/puppetlabs/puppetlabs-firewall/pull/715) ([pmcmaw](https://github.com/pmcmaw))
- (Modules-1141) No longer accepts an array for icmp types #puppethack [#705](https://github.com/puppetlabs/puppetlabs-firewall/pull/705) ([spynappels](https://github.com/spynappels))

### Added

- (MODULES-5144) Prep for puppet 5 [#709](https://github.com/puppetlabs/puppetlabs-firewall/pull/709) ([hunner](https://github.com/hunner))
- MODULE-1805 Add hashlimit-module [#708](https://github.com/puppetlabs/puppetlabs-firewall/pull/708) ([jtruestedt](https://github.com/jtruestedt))
- (MODULES-5111) Support UNTRACKED in state and ctstate rules [#707](https://github.com/puppetlabs/puppetlabs-firewall/pull/707) ([spynappels](https://github.com/spynappels))
- MODULES-4828 version_requirement updated #puppethack [#704](https://github.com/puppetlabs/puppetlabs-firewall/pull/704) ([neilbinney](https://github.com/neilbinney))
- Add gid lookup [#682](https://github.com/puppetlabs/puppetlabs-firewall/pull/682) ([crispygoth](https://github.com/crispygoth))

### Fixed

- [MODULES-5924] Fix unmanaged rule regex when updating a iptable. [#729](https://github.com/puppetlabs/puppetlabs-firewall/pull/729) ([sathlan](https://github.com/sathlan))
- (MODULES-5692) Match more than a single space [#727](https://github.com/puppetlabs/puppetlabs-firewall/pull/727) ([hunner](https://github.com/hunner))
- (MODULES-5645) Choose correct IP version for hostname resolution [#721](https://github.com/puppetlabs/puppetlabs-firewall/pull/721) ([kpengboy](https://github.com/kpengboy))
- allow ip6tables to be disabled [#694](https://github.com/puppetlabs/puppetlabs-firewall/pull/694) ([knackaron](https://github.com/knackaron))
- (MODULES-4200) Add simple sanity check for the rule to hash parser [#666](https://github.com/puppetlabs/puppetlabs-firewall/pull/666) ([comel](https://github.com/comel))

### Other

- (MODULES-5340) Understand negated match sets [#713](https://github.com/puppetlabs/puppetlabs-firewall/pull/713) ([nbarrientos](https://github.com/nbarrientos))

## [1.9.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.9.0) - 2017-05-19

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.8.2...1.9.0)

### Added

- (FM-4896) add NFLOG support [#697](https://github.com/puppetlabs/puppetlabs-firewall/pull/697) ([eputnam](https://github.com/eputnam))
- (MODULES-4234) Add support for --physdev-is-{in,out} [#685](https://github.com/puppetlabs/puppetlabs-firewall/pull/685) ([mhutter](https://github.com/mhutter))
- Allow managing ebtables [#684](https://github.com/puppetlabs/puppetlabs-firewall/pull/684) ([hunner](https://github.com/hunner))
- MODULES-4279 Add support for the geoip module [#680](https://github.com/puppetlabs/puppetlabs-firewall/pull/680) ([jg-development](https://github.com/jg-development))

### Fixed

- (maint) modify to account for spaces in iptables-save output [#700](https://github.com/puppetlabs/puppetlabs-firewall/pull/700) ([eputnam](https://github.com/eputnam))
- Change - Ensure that firewalld is stopped before iptables starts [#695](https://github.com/puppetlabs/puppetlabs-firewall/pull/695) ([blackknight36](https://github.com/blackknight36))
- Properly handle negated `--physdev-is-...` rules [#693](https://github.com/puppetlabs/puppetlabs-firewall/pull/693) ([mhutter](https://github.com/mhutter))
- MODULES-4279 use complete option for geoip [#690](https://github.com/puppetlabs/puppetlabs-firewall/pull/690) ([jg-development](https://github.com/jg-development))

## [1.8.2](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.8.2) - 2017-01-10

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.8.1...1.8.2)

### Added

- Add RHEL7 SELinux support for new service_name_v6 param, subsequently fix puppet lint error [#671](https://github.com/puppetlabs/puppetlabs-firewall/pull/671) ([wilson208](https://github.com/wilson208))
- [#puppethack] MODULES-1222 - added containment [#667](https://github.com/puppetlabs/puppetlabs-firewall/pull/667) ([genebean](https://github.com/genebean))
- Add --wait to iptables commands [#647](https://github.com/puppetlabs/puppetlabs-firewall/pull/647) ([mwhahaha](https://github.com/mwhahaha))

### Fixed

- Fixes SELinux compatibility with EL6 [#664](https://github.com/puppetlabs/puppetlabs-firewall/pull/664) ([bmjen](https://github.com/bmjen))
- Re-add RHEL7 SELinux support for puppet3 [#660](https://github.com/puppetlabs/puppetlabs-firewall/pull/660) ([bmjen](https://github.com/bmjen))
- Fixing issue with double quotes being removed when part of the comment [#646](https://github.com/puppetlabs/puppetlabs-firewall/pull/646) ([kindred](https://github.com/kindred))
- Implemented paramters for NFQUEUE jump target [#644](https://github.com/puppetlabs/puppetlabs-firewall/pull/644) ([pid1co](https://github.com/pid1co))
- (MODULES-3572) Ip6tables service is not managed in the redhat family. [#641](https://github.com/puppetlabs/puppetlabs-firewall/pull/641) ([marcofl](https://github.com/marcofl))

## [1.8.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.8.1) - 2016-05-17

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.8.0...1.8.1)

### Changed

- (maint) Remove nat flush [#625](https://github.com/puppetlabs/puppetlabs-firewall/pull/625) ([hunner](https://github.com/hunner))

### Added

- (Modules 3329) Add support for iptables length and string extensions [#630](https://github.com/puppetlabs/puppetlabs-firewall/pull/630) ([shumbert](https://github.com/shumbert))
- Add VirtuozzoLinux to the RedHat family [#617](https://github.com/puppetlabs/puppetlabs-firewall/pull/617) ([jpnc](https://github.com/jpnc))
- support for multiple ipsets in a rule [#615](https://github.com/puppetlabs/puppetlabs-firewall/pull/615) ([nabam](https://github.com/nabam))
- Add 'ip' and 'pim' to proto [#610](https://github.com/puppetlabs/puppetlabs-firewall/pull/610) ([lunkwill42](https://github.com/lunkwill42))

### Fixed

- allow FreeBSD when dependencies require this class [#624](https://github.com/puppetlabs/puppetlabs-firewall/pull/624) ([rcalixte](https://github.com/rcalixte))
- match rules with -m ttl [#612](https://github.com/puppetlabs/puppetlabs-firewall/pull/612) ([pulecp](https://github.com/pulecp))

## [1.8.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.8.0) - 2016-02-17

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.7.2...1.8.0)

### Added

- (MODULES-3079) Add support for goto argument. [#606](https://github.com/puppetlabs/puppetlabs-firewall/pull/606) ([aequitas](https://github.com/aequitas))
- allow iptables package to be updated [#583](https://github.com/puppetlabs/puppetlabs-firewall/pull/583) ([cristifalcas](https://github.com/cristifalcas))
- Support IPv6 NAT on Linux 3.7+ [#576](https://github.com/puppetlabs/puppetlabs-firewall/pull/576) ([nward](https://github.com/nward))

### Fixed

- Made Facter flushing specific to a single fact. [#604](https://github.com/puppetlabs/puppetlabs-firewall/pull/604) ([jonnytdevops](https://github.com/jonnytdevops))
- (MODULES 3932) - We need to call Facter.flush to clear Facter cache [#603](https://github.com/puppetlabs/puppetlabs-firewall/pull/603) ([jonnytdevops](https://github.com/jonnytdevops))
- (MODULES-2159) ignore the --connlimit-saddr switch when parsing rules [#602](https://github.com/puppetlabs/puppetlabs-firewall/pull/602) ([paulseward](https://github.com/paulseward))
- Adding in log_uid boolean for LOG [#593](https://github.com/puppetlabs/puppetlabs-firewall/pull/593) ([mlosapio](https://github.com/mlosapio))
- (MODULES-2836) Fix handling of chains that contain '-f' [#579](https://github.com/puppetlabs/puppetlabs-firewall/pull/579) ([maxvozeler](https://github.com/maxvozeler))
- (MODULES-2783) Missing ip6tables service name [#578](https://github.com/puppetlabs/puppetlabs-firewall/pull/578) ([abednarik](https://github.com/abednarik))

## [1.7.2](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.7.2) - 2015-12-07

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.7.1...1.7.2)

### Added

- Add: sctp-protocol to "proto"-Parameter [#589](https://github.com/puppetlabs/puppetlabs-firewall/pull/589) ([DavidS](https://github.com/DavidS))
- MODULES-2769 - Add security table for iptables. [#575](https://github.com/puppetlabs/puppetlabs-firewall/pull/575) ([werekraken](https://github.com/werekraken))

### Fixed

- (MODULES-1341) Recover when deleting absent rules [#577](https://github.com/puppetlabs/puppetlabs-firewall/pull/577) ([reidmv](https://github.com/reidmv))
- (MAINT) RedHat 6 also uses unconfined_t [#574](https://github.com/puppetlabs/puppetlabs-firewall/pull/574) ([DavidS](https://github.com/DavidS))
- MODULES-2487 Improve port deprecation warning [#572](https://github.com/puppetlabs/puppetlabs-firewall/pull/572) ([roman-mueller](https://github.com/roman-mueller))

## [1.7.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.7.1) - 2015-08-24

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.7.0...1.7.1)

### Changed

- Deprecate port parameter [#570](https://github.com/puppetlabs/puppetlabs-firewall/pull/570) ([hunner](https://github.com/hunner))

### Fixed

- Always use dport [#569](https://github.com/puppetlabs/puppetlabs-firewall/pull/569) ([grigarr](https://github.com/grigarr))

## [1.7.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.7.0) - 2015-07-27

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.6.0...1.7.0)

### Added

- add set_dscp and set_dscp_class [#560](https://github.com/puppetlabs/puppetlabs-firewall/pull/560) ([estonfer](https://github.com/estonfer))
- Compatibility with Puppet 4 and Facter 3 [#559](https://github.com/puppetlabs/puppetlabs-firewall/pull/559) ([Jmeyering](https://github.com/Jmeyering))

### Fixed

- Makes all the services autorequired by the firewall and firewallchain types. [#556](https://github.com/puppetlabs/puppetlabs-firewall/pull/556) ([jonnytdevops](https://github.com/jonnytdevops))
- MODULES-2186 - iptables rules with -A in comment [#555](https://github.com/puppetlabs/puppetlabs-firewall/pull/555) ([TJM](https://github.com/TJM))
- Fix for physdev idempotency on EL5 [#551](https://github.com/puppetlabs/puppetlabs-firewall/pull/551) ([jonnytdevops](https://github.com/jonnytdevops))
- Fix addrtype inversion [#543](https://github.com/puppetlabs/puppetlabs-firewall/pull/543) ([jonnytdevops](https://github.com/jonnytdevops))
- (MODULES-1976) Revise rule name validation for ruby 1.9 [#517](https://github.com/puppetlabs/puppetlabs-firewall/pull/517) ([karmix](https://github.com/karmix))
- (MODULES-1967) Parse escape sequences from iptables [#513](https://github.com/puppetlabs/puppetlabs-firewall/pull/513) ([karmix](https://github.com/karmix))

## [1.6.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.6.0) - 2015-05-19

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.5.0...1.6.0)

### Added

- add match_mark [#527](https://github.com/puppetlabs/puppetlabs-firewall/pull/527) ([jonnytdevops](https://github.com/jonnytdevops))
- Tee Support [#525](https://github.com/puppetlabs/puppetlabs-firewall/pull/525) ([jonnytdevops](https://github.com/jonnytdevops))
- MSS feature [#524](https://github.com/puppetlabs/puppetlabs-firewall/pull/524) ([jonnytdevops](https://github.com/jonnytdevops))
- Added support for time ipt_module [#522](https://github.com/puppetlabs/puppetlabs-firewall/pull/522) ([jonnytdevops](https://github.com/jonnytdevops))
- Add support for ICMPv6 types neighbour-{solicitation,advertisement} [#515](https://github.com/puppetlabs/puppetlabs-firewall/pull/515) ([peikk0](https://github.com/peikk0))
- Add support for ICMPv6 type too-big (2) [#514](https://github.com/puppetlabs/puppetlabs-firewall/pull/514) ([peikk0](https://github.com/peikk0))
- Added ipv{4,6} to protocol list [#505](https://github.com/puppetlabs/puppetlabs-firewall/pull/505) ([jpds-zz](https://github.com/jpds-zz))

### Fixed

- Fix Arch Linux support [#526](https://github.com/puppetlabs/puppetlabs-firewall/pull/526) ([elyscape](https://github.com/elyscape))
- Added iptables-persistent fix for Debian 8 and Ubuntu 14.10 [#523](https://github.com/puppetlabs/puppetlabs-firewall/pull/523) ([jonnytdevops](https://github.com/jonnytdevops))
- Fixed idempotency bug relating to MODULES-1984 [#520](https://github.com/puppetlabs/puppetlabs-firewall/pull/520) ([jonnytdevops](https://github.com/jonnytdevops))
- (MODULES-1984) Perform daemon-reload on systemd [#518](https://github.com/puppetlabs/puppetlabs-firewall/pull/518) ([johnduarte](https://github.com/johnduarte))

## [1.5.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.5.0) - 2015-03-31

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.4.0...1.5.0)

### Added

- MODULES-1832 - add Gentoo support [#498](https://github.com/puppetlabs/puppetlabs-firewall/pull/498) ([derdanne](https://github.com/derdanne))
- MODULES-1636: Add --checksum-fill support. [#460](https://github.com/puppetlabs/puppetlabs-firewall/pull/460) ([Zlo](https://github.com/Zlo))

### Fixed

- MODULES-1808 - Implemented code for resource map munging to allow a single ipt module to be used multiple times in a single rule [#496](https://github.com/puppetlabs/puppetlabs-firewall/pull/496) ([jonnytdevops](https://github.com/jonnytdevops))
- Added code for physdev_is_bridged [#491](https://github.com/puppetlabs/puppetlabs-firewall/pull/491) ([jonnytdevops](https://github.com/jonnytdevops))

## [1.4.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.4.0) - 2015-01-27

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.3.0...1.4.0)

### Added

- Added support for iptables physdev_in and physdev_out parameters [#473](https://github.com/puppetlabs/puppetlabs-firewall/pull/473) ([jonnytdevops](https://github.com/jonnytdevops))
- MODULES-1612 - sync mask [#469](https://github.com/puppetlabs/puppetlabs-firewall/pull/469) ([underscorgan](https://github.com/underscorgan))
- MODULES-1612 - sync ipset [#468](https://github.com/puppetlabs/puppetlabs-firewall/pull/468) ([underscorgan](https://github.com/underscorgan))
- MODULES-1612 - sync set_mark [#464](https://github.com/puppetlabs/puppetlabs-firewall/pull/464) ([underscorgan](https://github.com/underscorgan))
- MODULES-1612 - Sync ipsec_dir and ipsec_policy [#459](https://github.com/puppetlabs/puppetlabs-firewall/pull/459) ([underscorgan](https://github.com/underscorgan))
- MODULES-1612 - sync mac_source [#454](https://github.com/puppetlabs/puppetlabs-firewall/pull/454) ([underscorgan](https://github.com/underscorgan))
- MODULES-1612 - sync src_type and dst_type [#453](https://github.com/puppetlabs/puppetlabs-firewall/pull/453) ([underscorgan](https://github.com/underscorgan))
- MODULES-1612 - sync src_range and dst_range [#452](https://github.com/puppetlabs/puppetlabs-firewall/pull/452) ([underscorgan](https://github.com/underscorgan))
- MODUELES-1355 - support dport/sport in ip6tables provider [#451](https://github.com/puppetlabs/puppetlabs-firewall/pull/451) ([underscorgan](https://github.com/underscorgan))
- (MODULES-464) Add netmap feature [#421](https://github.com/puppetlabs/puppetlabs-firewall/pull/421) ([patrobinson](https://github.com/patrobinson))

### Fixed

- MODULES-1453 - overly aggressive gsub [#479](https://github.com/puppetlabs/puppetlabs-firewall/pull/479) ([underscorgan](https://github.com/underscorgan))
- Uid negation fix [#474](https://github.com/puppetlabs/puppetlabs-firewall/pull/474) ([jonnytdevops](https://github.com/jonnytdevops))
- QENG-1678 - Need to stop iptables to install ipset [#472](https://github.com/puppetlabs/puppetlabs-firewall/pull/472) ([underscorgan](https://github.com/underscorgan))
- Fixing regressions for Amazon Linux since RH7 support was added [#471](https://github.com/puppetlabs/puppetlabs-firewall/pull/471) ([mlehner616](https://github.com/mlehner616))
- MODULES-1612 - mask isn't supported on deb7 [#470](https://github.com/puppetlabs/puppetlabs-firewall/pull/470) ([underscorgan](https://github.com/underscorgan))
- MODULES-1552 - Issues parsing `-m (tcp|udp)` rules [#462](https://github.com/puppetlabs/puppetlabs-firewall/pull/462) ([underscorgan](https://github.com/underscorgan))

## [1.3.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.3.0) - 2014-12-16

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.2.0...1.3.0)

### Added

- MODULES-556: tcp_flags support for ip6tables [#442](https://github.com/puppetlabs/puppetlabs-firewall/pull/442) ([underscorgan](https://github.com/underscorgan))
- MODULES-1309 - Make package and service names configurable [#436](https://github.com/puppetlabs/puppetlabs-firewall/pull/436) ([underscorgan](https://github.com/underscorgan))
- MODULES-1469 MODULES-1470 Support alias (eth0:0), negation for iniface, ... [#435](https://github.com/puppetlabs/puppetlabs-firewall/pull/435) ([underscorgan](https://github.com/underscorgan))
- FM-2022 Add SLES 12 to metadata [#434](https://github.com/puppetlabs/puppetlabs-firewall/pull/434) ([cyberious](https://github.com/cyberious))

### Fixed

- MODULES-1572 - Fix logic broken from MODULES-1309 [#441](https://github.com/puppetlabs/puppetlabs-firewall/pull/441) ([underscorgan](https://github.com/underscorgan))
- MODULES-1565 - Fix regexes for EL5 [#438](https://github.com/puppetlabs/puppetlabs-firewall/pull/438) ([underscorgan](https://github.com/underscorgan))
- Don't arbitrarily limit set_mark to certain chains [#427](https://github.com/puppetlabs/puppetlabs-firewall/pull/427) ([stesie](https://github.com/stesie))

## [1.2.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.2.0) - 2014-11-04

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.1.3...1.2.0)

### Changed

- Doesn't actually support OEL5 [#418](https://github.com/puppetlabs/puppetlabs-firewall/pull/418) ([underscorgan](https://github.com/underscorgan))

### Added

- Update to support PE3.x [#420](https://github.com/puppetlabs/puppetlabs-firewall/pull/420) ([underscorgan](https://github.com/underscorgan))
- Support netfilter-persistent for later versions [#403](https://github.com/puppetlabs/puppetlabs-firewall/pull/403) ([rra](https://github.com/rra))
- (MODULES-450) Enable rule inversion [#394](https://github.com/puppetlabs/puppetlabs-firewall/pull/394) ([hunner](https://github.com/hunner))
- Add cbt protocol, to be able to mitigate some DDoS attacks [#388](https://github.com/puppetlabs/puppetlabs-firewall/pull/388) ([thias](https://github.com/thias))
- add ipset support [#383](https://github.com/puppetlabs/puppetlabs-firewall/pull/383) ([vzctl](https://github.com/vzctl))
- Add support for mac address source rules pt2 [#337](https://github.com/puppetlabs/puppetlabs-firewall/pull/337) ([damjanek](https://github.com/damjanek))

### Fixed

- ip6tables isn't supported on EL5 [#428](https://github.com/puppetlabs/puppetlabs-firewall/pull/428) ([underscorgan](https://github.com/underscorgan))
- Fixed firewalld package issue [#426](https://github.com/puppetlabs/puppetlabs-firewall/pull/426) ([paramite](https://github.com/paramite))
- (MODULES-41) Change source for ip6tables provider [#422](https://github.com/puppetlabs/puppetlabs-firewall/pull/422) ([hunner](https://github.com/hunner))
- (MODULES-1086) toports is not reqired with jump == REDIRECT [#407](https://github.com/puppetlabs/puppetlabs-firewall/pull/407) ([hunner](https://github.com/hunner))
- Bugfix stat_prob -> stat_probability [#402](https://github.com/puppetlabs/puppetlabs-firewall/pull/402) ([hunner](https://github.com/hunner))
- Improve support for EL7 and other related fixes [#393](https://github.com/puppetlabs/puppetlabs-firewall/pull/393) ([hunner](https://github.com/hunner))
- Fixed bug which arbitrarily limited iniface and outiface parameters [#374](https://github.com/puppetlabs/puppetlabs-firewall/pull/374) ([lejonet](https://github.com/lejonet))

## [1.1.3](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.1.3) - 2014-07-14

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.1.2...1.1.3)

## [1.1.2](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.1.2) - 2014-06-05

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.1.1...1.1.2)

### Fixed

- (MODULES-796) Fix policy ipsec options [#363](https://github.com/puppetlabs/puppetlabs-firewall/pull/363) ([hunner](https://github.com/hunner))

## [1.1.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.1.1) - 2014-05-16

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.1.0...1.1.1)

## [1.1.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.1.0) - 2014-05-13

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.0.2...1.1.0)

### Changed

- Apply firewall resources alphabetically [#342](https://github.com/puppetlabs/puppetlabs-firewall/pull/342) ([mcanevet](https://github.com/mcanevet))

### Added

- (MODULES-689) Add support for connlimit and connmark [#344](https://github.com/puppetlabs/puppetlabs-firewall/pull/344) ([csschwe](https://github.com/csschwe))

### Fixed

- Fix access to distmoduledir [#354](https://github.com/puppetlabs/puppetlabs-firewall/pull/354) ([hunner](https://github.com/hunner))
- Fix support for Fedora Rawhide [#350](https://github.com/puppetlabs/puppetlabs-firewall/pull/350) ([xbezdick](https://github.com/xbezdick))
- Fix failing persist_iptables test on RHEL7 and Fedora [#341](https://github.com/puppetlabs/puppetlabs-firewall/pull/341) ([jeckersb](https://github.com/jeckersb))
- --reap flag is not added to iptables command [#340](https://github.com/puppetlabs/puppetlabs-firewall/pull/340) ([simon-martin](https://github.com/simon-martin))
- Fix typo in SNAT error message [#339](https://github.com/puppetlabs/puppetlabs-firewall/pull/339) ([cure](https://github.com/cure))
- Treat RHEL 7 and later like Fedora w/r/t iptables [#338](https://github.com/puppetlabs/puppetlabs-firewall/pull/338) ([larsks](https://github.com/larsks))

## [1.0.2](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.0.2) - 2014-03-04

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.0.1...1.0.2)

### Fixed

- Replace the symlink with the actual file to resolve a PMT issue. [#331](https://github.com/puppetlabs/puppetlabs-firewall/pull/331) ([apenney](https://github.com/apenney))

## [1.0.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.0.1) - 2014-03-03

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.0.0...1.0.1)

### Fixed

- Change OEL limitation description [#326](https://github.com/puppetlabs/puppetlabs-firewall/pull/326) ([hunner](https://github.com/hunner))
- Socket owner sles madness [#324](https://github.com/puppetlabs/puppetlabs-firewall/pull/324) ([apenney](https://github.com/apenney))
- Fix logic for supported socket platforms [#322](https://github.com/puppetlabs/puppetlabs-firewall/pull/322) ([hunner](https://github.com/hunner))
- Bugfix: Account for rules sorted after unmanaged rules [#321](https://github.com/puppetlabs/puppetlabs-firewall/pull/321) ([hunner](https://github.com/hunner))
- Fix various differences for rhel5 [#314](https://github.com/puppetlabs/puppetlabs-firewall/pull/314) ([hunner](https://github.com/hunner))
- Use iptables-save and parse the output [#311](https://github.com/puppetlabs/puppetlabs-firewall/pull/311) ([hunner](https://github.com/hunner))

## [1.0.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.0.0) - 2014-02-11

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/0.5.0...1.0.0)

## [0.5.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/0.5.0) - 2014-02-10

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/0.4.2...0.5.0)

### Added

- Add --random support as per #141 comment [#298](https://github.com/puppetlabs/puppetlabs-firewall/pull/298) ([hunner](https://github.com/hunner))
- (MODULES-31) add support for iptables recent [#296](https://github.com/puppetlabs/puppetlabs-firewall/pull/296) ([hunner](https://github.com/hunner))
- Add purge support to firewallchain [#287](https://github.com/puppetlabs/puppetlabs-firewall/pull/287) ([hunner](https://github.com/hunner))
- allow input chain in nat table [#270](https://github.com/puppetlabs/puppetlabs-firewall/pull/270) ([phemmer](https://github.com/phemmer))
- add ipsec policy matching [#268](https://github.com/puppetlabs/puppetlabs-firewall/pull/268) ([phemmer](https://github.com/phemmer))
- Negation support [#267](https://github.com/puppetlabs/puppetlabs-firewall/pull/267) ([phemmer](https://github.com/phemmer))
- Support conntrack stateful firewall matching [#257](https://github.com/puppetlabs/puppetlabs-firewall/pull/257) ([nogweii](https://github.com/nogweii))
- Add support for IPv6 hop limiting [#208](https://github.com/puppetlabs/puppetlabs-firewall/pull/208) ([georgkoester](https://github.com/georgkoester))
- Add ipv6 frag matchers2 and generify known_boolean handling. [#207](https://github.com/puppetlabs/puppetlabs-firewall/pull/207) ([georgkoester](https://github.com/georgkoester))

### Fixed

- Fix for #286 for pre-existing rules at the start of a chain [#303](https://github.com/puppetlabs/puppetlabs-firewall/pull/303) ([hunner](https://github.com/hunner))
- Fix #300 for match extension protocol [#302](https://github.com/puppetlabs/puppetlabs-firewall/pull/302) ([hunner](https://github.com/hunner))
- (MODULES-451) Match extension protocol for multiport [#300](https://github.com/puppetlabs/puppetlabs-firewall/pull/300) ([hunner](https://github.com/hunner))
- (MODULES-16) Correct src_range dst_range ordering [#293](https://github.com/puppetlabs/puppetlabs-firewall/pull/293) ([hunner](https://github.com/hunner))
- (MODULES-442) Correct boolean properties behavior [#291](https://github.com/puppetlabs/puppetlabs-firewall/pull/291) ([hunner](https://github.com/hunner))
- (MODULES-441) Helpfully fail when modifying chains [#288](https://github.com/puppetlabs/puppetlabs-firewall/pull/288) ([hunner](https://github.com/hunner))
- (MODULES-439) Work around existing rules [#286](https://github.com/puppetlabs/puppetlabs-firewall/pull/286) ([hunner](https://github.com/hunner))
- fix handling of builtin chains [#271](https://github.com/puppetlabs/puppetlabs-firewall/pull/271) ([phemmer](https://github.com/phemmer))
- Remove redundant `include` call in system spec helper. [#253](https://github.com/puppetlabs/puppetlabs-firewall/pull/253) ([stefanozanella](https://github.com/stefanozanella))
- Generate parser list [#248](https://github.com/puppetlabs/puppetlabs-firewall/pull/248) ([senax](https://github.com/senax))
- No firewallchain autorequire for INPUT, OUTPUT and FORWARD when table is :filter to enable DROP policy without blocking [#240](https://github.com/puppetlabs/puppetlabs-firewall/pull/240) ([doc75](https://github.com/doc75))

## [0.4.2](https://github.com/puppetlabs/puppetlabs-firewall/tree/0.4.2) - 2013-09-10

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/0.4.1...0.4.2)

## [0.4.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/0.4.1) - 2013-08-12

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/0.4.0...0.4.1)

## [0.4.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/0.4.0) - 2013-07-12

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/list...0.4.0)

### Added

- Feature/master/add support for iprange [#219](https://github.com/puppetlabs/puppetlabs-firewall/pull/219) ([hunner](https://github.com/hunner))

## [list](https://github.com/puppetlabs/puppetlabs-firewall/tree/list) - 2013-07-09

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/0.3.1...list)

### Added

- Add SL and SLC cases for operatingsystem [#220](https://github.com/puppetlabs/puppetlabs-firewall/pull/220) ([traylenator](https://github.com/traylenator))
- Add support for --src-type and --dst-type [#212](https://github.com/puppetlabs/puppetlabs-firewall/pull/212) ([nickstenning](https://github.com/nickstenning))

### Fixed

- Update providers to use expect syntax [#217](https://github.com/puppetlabs/puppetlabs-firewall/pull/217) ([hunner](https://github.com/hunner))
- Fix #188: -f in comment leads to puppet resource firewall failing. [#204](https://github.com/puppetlabs/puppetlabs-firewall/pull/204) ([georgkoester](https://github.com/georgkoester))

## [0.3.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/0.3.1) - 2013-06-10

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/0.3.0...0.3.1)

### Fixed

- Ensure all services have 'hasstatus => true' for Puppet 2.6 [#197](https://github.com/puppetlabs/puppetlabs-firewall/pull/197) ([kbarber](https://github.com/kbarber))
- Accept pre-existing rule with invalid name [#192](https://github.com/puppetlabs/puppetlabs-firewall/pull/192) ([joejulian](https://github.com/joejulian))
- Swap log_prefix and log_level order to match the way it's saved [#191](https://github.com/puppetlabs/puppetlabs-firewall/pull/191) ([joejulian](https://github.com/joejulian))
- (#20912) Split argments while maintaining quoted strings [#189](https://github.com/puppetlabs/puppetlabs-firewall/pull/189) ([joejulian](https://github.com/joejulian))

## [0.3.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/0.3.0) - 2013-04-25

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/0.2.1...0.3.0)

### Added

- (#171) Added ensure parameter to firewall class [#172](https://github.com/puppetlabs/puppetlabs-firewall/pull/172) ([cr3](https://github.com/cr3))
- (20096) Support systemd on Fedora 15 and up [#145](https://github.com/puppetlabs/puppetlabs-firewall/pull/145) ([ecbypi](https://github.com/ecbypi))

### Fixed

- Duplicate existing rules dont purge [#166](https://github.com/puppetlabs/puppetlabs-firewall/pull/166) ([kbarber](https://github.com/kbarber))
- Booleans not idempotent [#162](https://github.com/puppetlabs/puppetlabs-firewall/pull/162) ([kbarber](https://github.com/kbarber))

## [0.2.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/0.2.1) - 2013-03-13

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/0.2.0...0.2.1)

## [0.2.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/0.2.0) - 2013-03-03

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/0.1.1...0.2.0)

### Added

- (GH-134) Autorequire iptables related packages [#136](https://github.com/puppetlabs/puppetlabs-firewall/pull/136) ([dcarley](https://github.com/dcarley))

### Fixed

- Native persistence [#133](https://github.com/puppetlabs/puppetlabs-firewall/pull/133) ([dcarley](https://github.com/dcarley))

## [0.1.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/0.1.1) - 2013-02-28

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/0.1.0...0.1.1)

## [0.1.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/0.1.0) - 2013-02-24

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v0.0.4...0.1.0)

### Added

- (#15556) Support for ICMP6 type code resolutions [#87](https://github.com/puppetlabs/puppetlabs-firewall/pull/87) ([dcarley](https://github.com/dcarley))
- (#15038) add gre protocol to list of acceptable protocols [#85](https://github.com/puppetlabs/puppetlabs-firewall/pull/85) ([jasonhancock](https://github.com/jasonhancock))
- Ticket/11305 support vlan interface [#70](https://github.com/puppetlabs/puppetlabs-firewall/pull/70) ([kbarber](https://github.com/kbarber))
- Ticket/10162 firewallchain support for merge [#62](https://github.com/puppetlabs/puppetlabs-firewall/pull/62) ([kbarber](https://github.com/kbarber))

### Fixed

- Mock Resolv.getaddress in #host_to_ip [#110](https://github.com/puppetlabs/puppetlabs-firewall/pull/110) ([dcarley](https://github.com/dcarley))
- ip6tables provider allways execute /sbin/iptables command [#105](https://github.com/puppetlabs/puppetlabs-firewall/pull/105) ([wuwx](https://github.com/wuwx))
- (#10322) Insert order hash included chains from different tables [#89](https://github.com/puppetlabs/puppetlabs-firewall/pull/89) ([kbarber](https://github.com/kbarber))
- (#10274) Nullify addresses with zero prefixlen [#80](https://github.com/puppetlabs/puppetlabs-firewall/pull/80) ([dcarley](https://github.com/dcarley))
- Ticket/10619 unable to purge rules [#69](https://github.com/puppetlabs/puppetlabs-firewall/pull/69) ([kbarber](https://github.com/kbarber))
- (#13201) Firewall autorequire Firewallchains [#67](https://github.com/puppetlabs/puppetlabs-firewall/pull/67) ([dcarley](https://github.com/dcarley))
- (#13192) Fix allvalidchain iteration [#63](https://github.com/puppetlabs/puppetlabs-firewall/pull/63) ([kbarber](https://github.com/kbarber))
- Improved Puppet DSL style as per the guidelines. [#61](https://github.com/puppetlabs/puppetlabs-firewall/pull/61) ([adamgibbins](https://github.com/adamgibbins))
- (#10164) Reject and document icmp => "any" [#60](https://github.com/puppetlabs/puppetlabs-firewall/pull/60) ([dcarley](https://github.com/dcarley))
- (#11443) simple fix of the error message for allowed values of the jump property [#50](https://github.com/puppetlabs/puppetlabs-firewall/pull/50) ([grooverdan](https://github.com/grooverdan))

## [v0.0.4](https://github.com/puppetlabs/puppetlabs-firewall/tree/v0.0.4) - 2011-12-05

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v0.0.3...v0.0.4)

### Added

- (#10690) add port property support to ip6tables [#33](https://github.com/puppetlabs/puppetlabs-firewall/pull/33) ([saysjonathan](https://github.com/saysjonathan))

## [v0.0.3](https://github.com/puppetlabs/puppetlabs-firewall/tree/v0.0.3) - 2011-11-12

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v0.0.2...v0.0.3)

### Fixed

- (#10700) allow additional characters in comment string [#30](https://github.com/puppetlabs/puppetlabs-firewall/pull/30) ([saysjonathan](https://github.com/saysjonathan))

## [v0.0.2](https://github.com/puppetlabs/puppetlabs-firewall/tree/v0.0.2) - 2011-10-26

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v0.0.1...v0.0.2)

### Added

- (#9362) Create action property and perform transformation for accept, dro [#15](https://github.com/puppetlabs/puppetlabs-firewall/pull/15) ([kbarber](https://github.com/kbarber))

### Fixed

- (#10295) Work around bug #4248 whereby the puppet/util paths are not bein [#22](https://github.com/puppetlabs/puppetlabs-firewall/pull/22) ([kbarber](https://github.com/kbarber))
- (#10002) Change to dport and sport to handle ranges, and fix handling of  [#21](https://github.com/puppetlabs/puppetlabs-firewall/pull/21) ([kbarber](https://github.com/kbarber))

## [v0.0.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/v0.0.1) - 2011-10-18

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/bff53bdbc03ad416e3f23d7ad943ebdffb3bd999...v0.0.1)
