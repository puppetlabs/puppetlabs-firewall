# Change log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](http://semver.org).

## [v5.0.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v5.0.0) (2023-03-31)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v4.1.0...v5.0.0)

### Changed

- \(Cont 779\) Add Support for Puppet 8 / Drop Support for Puppet 6 [\#1118](https://github.com/puppetlabs/puppetlabs-firewall/pull/1118) ([david22swan](https://github.com/david22swan))

## [v4.1.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v4.1.0) (2023-03-31)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v4.0.1...v4.1.0)

### Added

- \(CONT-352\) Syntax update [\#1110](https://github.com/puppetlabs/puppetlabs-firewall/pull/1110) ([LukasAud](https://github.com/LukasAud))

### Fixed

- Ignore OpenBSD, similarly to FreeBSD [\#1107](https://github.com/puppetlabs/puppetlabs-firewall/pull/1107) ([buzzdeee](https://github.com/buzzdeee))
- redhat9 needs iptables service [\#1103](https://github.com/puppetlabs/puppetlabs-firewall/pull/1103) ([robertc99](https://github.com/robertc99))
- debian: service: fix `ensure` parameter usage [\#1095](https://github.com/puppetlabs/puppetlabs-firewall/pull/1095) ([damonbreeden](https://github.com/damonbreeden))

## [v4.0.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/v4.0.1) (2022-12-07)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v4.0.0...v4.0.1)

### Fixed

- \(GH-1097\) Bumping back required puppet version [\#1098](https://github.com/puppetlabs/puppetlabs-firewall/pull/1098) ([LukasAud](https://github.com/LukasAud))
- support --nflog-size as replacement for --nflog-range [\#1096](https://github.com/puppetlabs/puppetlabs-firewall/pull/1096) ([kjetilho](https://github.com/kjetilho))
- \(1093\) - Fix unresolved fact error [\#1094](https://github.com/puppetlabs/puppetlabs-firewall/pull/1094) ([jordanbreen28](https://github.com/jordanbreen28))
- package "iptables" has been replaced by "iptables-nft" on EL9 [\#1085](https://github.com/puppetlabs/puppetlabs-firewall/pull/1085) ([kjetilho](https://github.com/kjetilho))

## [v4.0.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v4.0.0) (2022-11-22)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.6.0...v4.0.0)

### Changed

- \(CONT-256\) Removing outdated code [\#1084](https://github.com/puppetlabs/puppetlabs-firewall/pull/1084) ([LukasAud](https://github.com/LukasAud))

### Added

- add support for using rpfilter in rules [\#1059](https://github.com/puppetlabs/puppetlabs-firewall/pull/1059) ([cmusik](https://github.com/cmusik))

### Fixed

- \(CONT-173\) - Updating deprecated facter instances [\#1079](https://github.com/puppetlabs/puppetlabs-firewall/pull/1079) ([jordanbreen28](https://github.com/jordanbreen28))
- pdksync - \(CONT-189\) Remove support for RedHat6 / OracleLinux6 / Scientific6 [\#1078](https://github.com/puppetlabs/puppetlabs-firewall/pull/1078) ([david22swan](https://github.com/david22swan))
- pdksync - \(CONT-130\) - Dropping Support for Debian 9 [\#1075](https://github.com/puppetlabs/puppetlabs-firewall/pull/1075) ([jordanbreen28](https://github.com/jordanbreen28))
- fix service port number lookup to use protocol [\#1023](https://github.com/puppetlabs/puppetlabs-firewall/pull/1023) ([kjetilho](https://github.com/kjetilho))

## [v3.6.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.6.0) (2022-10-03)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.5.0...v3.6.0)

### Added

- pdksync - \(GH-cat-11\) Certify Support for Ubuntu 22.04 [\#1063](https://github.com/puppetlabs/puppetlabs-firewall/pull/1063) ([david22swan](https://github.com/david22swan))
- pdksync - \(GH-cat-12\) Add Support for Redhat 9 [\#1054](https://github.com/puppetlabs/puppetlabs-firewall/pull/1054) ([david22swan](https://github.com/david22swan))

### Fixed

- allow persistence of firewall rules for Suse [\#1061](https://github.com/puppetlabs/puppetlabs-firewall/pull/1061) ([corporate-gadfly](https://github.com/corporate-gadfly))
- \(GH-1055\) Fix for `--random-fully` [\#1058](https://github.com/puppetlabs/puppetlabs-firewall/pull/1058) ([david22swan](https://github.com/david22swan))

## [v3.5.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.5.0) (2022-05-17)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.4.0...v3.5.0)

### Added

- CentOS Stream 9 Support \(should include RHEL9 when that releases\) [\#1028](https://github.com/puppetlabs/puppetlabs-firewall/pull/1028) ([tskirvin](https://github.com/tskirvin))

### Fixed

- pdksync - \(GH-iac-334\) Remove Support for Ubuntu 14.04/16.04 [\#1038](https://github.com/puppetlabs/puppetlabs-firewall/pull/1038) ([david22swan](https://github.com/david22swan))
- Fix rpfilter parameter [\#1013](https://github.com/puppetlabs/puppetlabs-firewall/pull/1013) ([onyxmaster](https://github.com/onyxmaster))

## [v3.4.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.4.0) (2022-02-28)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.3.0...v3.4.0)

### Added

- \(SEC-944\) Handle duplicate system rules [\#1030](https://github.com/puppetlabs/puppetlabs-firewall/pull/1030) ([chelnak](https://github.com/chelnak))

### Fixed

- pdksync - \(IAC-1787\) Remove Support for CentOS 6 [\#1027](https://github.com/puppetlabs/puppetlabs-firewall/pull/1027) ([david22swan](https://github.com/david22swan))

## [v3.3.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.3.0) (2021-12-15)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.2.0...v3.3.0)

### Changed

- pdksync - \(MAINT\) Remove SLES 11 support [\#977](https://github.com/puppetlabs/puppetlabs-firewall/pull/977) ([sanfrancrisko](https://github.com/sanfrancrisko))

### Added

- pdksync - \(IAC-1753\) - Add Support for AlmaLinux 8 [\#1020](https://github.com/puppetlabs/puppetlabs-firewall/pull/1020) ([david22swan](https://github.com/david22swan))
- pdksync - \(IAC-1751\) - Add Support for Rocky 8 [\#1017](https://github.com/puppetlabs/puppetlabs-firewall/pull/1017) ([david22swan](https://github.com/david22swan))

### Fixed

- Bugfix MODULES-11203: error on second apply when uid or gid is specified as a range [\#1019](https://github.com/puppetlabs/puppetlabs-firewall/pull/1019) ([cmd-ntrf](https://github.com/cmd-ntrf))
- Fedora 34 and iptables-compat fix; properly utilising iptables param. [\#1018](https://github.com/puppetlabs/puppetlabs-firewall/pull/1018) ([adamboutcher](https://github.com/adamboutcher))
- pdksync - \(IAC-1598\) - Remove Support for Debian 8 [\#1015](https://github.com/puppetlabs/puppetlabs-firewall/pull/1015) ([david22swan](https://github.com/david22swan))
- Add carp protocol to :proto property [\#1014](https://github.com/puppetlabs/puppetlabs-firewall/pull/1014) ([adrianiurca](https://github.com/adrianiurca))
- \(MODULES-6876\) lib/puppet/provider/firewall/iptables.rb - comments cleanup for parsing [\#981](https://github.com/puppetlabs/puppetlabs-firewall/pull/981) ([tskirvin](https://github.com/tskirvin))

## [v3.2.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.2.0) (2021-09-06)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.1.0...v3.2.0)

### Added

- pdksync - \(IAC-1709\) - Add Support for Debian 11 [\#1005](https://github.com/puppetlabs/puppetlabs-firewall/pull/1005) ([david22swan](https://github.com/david22swan))

### Fixed

- Fix "undefined method `gsub' for nil:NilClass" when changing existing rule UID from absent to any present [\#1010](https://github.com/puppetlabs/puppetlabs-firewall/pull/1010) ([onyxmaster](https://github.com/onyxmaster))

## [v3.1.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.1.0) (2021-07-26)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.0.2...v3.1.0)

### Added

- add compatibility with Rocky Linux [\#998](https://github.com/puppetlabs/puppetlabs-firewall/pull/998) ([vchepkov](https://github.com/vchepkov))

### Fixed

- \(MODULES-11138\) - Fix mac\_source Facter.fact\(\).value\(\) issue with Facter 3 [\#1002](https://github.com/puppetlabs/puppetlabs-firewall/pull/1002) ([adrianiurca](https://github.com/adrianiurca))

## [v3.0.2](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.0.2) (2021-07-19)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.0.1...v3.0.2)

### Fixed

- sles-15: mac\_source is downcased by iptables [\#997](https://github.com/puppetlabs/puppetlabs-firewall/pull/997) ([adrianiurca](https://github.com/adrianiurca))
- fix: parsing random\_fully in ip6tables [\#996](https://github.com/puppetlabs/puppetlabs-firewall/pull/996) ([scoiatael](https://github.com/scoiatael))

## [v3.0.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.0.1) (2021-06-21)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v3.0.0...v3.0.1)

### Fixed

- Fixed link to REFERENCE.md [\#993](https://github.com/puppetlabs/puppetlabs-firewall/pull/993) ([Samgarr](https://github.com/Samgarr))
- Update README.md [\#986](https://github.com/puppetlabs/puppetlabs-firewall/pull/986) ([arjenz](https://github.com/arjenz))

## [v3.0.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v3.0.0) (2021-03-01)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.8.1...v3.0.0)

### Changed

- pdksync - \(MAINT\) Remove SLES 11 support [\#977](https://github.com/puppetlabs/puppetlabs-firewall/pull/977) ([sanfrancrisko](https://github.com/sanfrancrisko))
- pdksync - \(MAINT\) Remove RHEL 5 family support [\#976](https://github.com/puppetlabs/puppetlabs-firewall/pull/976) ([sanfrancrisko](https://github.com/sanfrancrisko))
- pdksync - Remove Puppet 5 from testing and bump minimal version to 6.0.0 [\#972](https://github.com/puppetlabs/puppetlabs-firewall/pull/972) ([carabasdaniel](https://github.com/carabasdaniel))

## [v2.8.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.8.1) (2021-02-09)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.8.0...v2.8.1)

### Fixed

- \[MODULES-10907\] Do not remove spaces from hex string with ! [\#967](https://github.com/puppetlabs/puppetlabs-firewall/pull/967) ([adrianiurca](https://github.com/adrianiurca))

## [v2.8.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.8.0) (2020-12-14)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.7.0...v2.8.0)

### Added

- pdksync - \(feat\) - Add support for Puppet 7 [\#959](https://github.com/puppetlabs/puppetlabs-firewall/pull/959) ([daianamezdrea](https://github.com/daianamezdrea))
- \(IAC-966\) - MODULES-10522: Add support for the --condition parameter [\#941](https://github.com/puppetlabs/puppetlabs-firewall/pull/941) ([adrianiurca](https://github.com/adrianiurca))

### Fixed

- Restore copyright names [\#951](https://github.com/puppetlabs/puppetlabs-firewall/pull/951) ([hunner](https://github.com/hunner))

## [v2.7.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.7.0) (2020-10-15)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.6.0...v2.7.0)

### Added

- \(IAC-1190\) add `ignore_foreign` when purging firewallchains [\#948](https://github.com/puppetlabs/puppetlabs-firewall/pull/948) ([DavidS](https://github.com/DavidS))

## [v2.6.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.6.0) (2020-10-01)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.5.0...v2.6.0)

### Fixed

- Fix extra quotes in firewall string matching [\#944](https://github.com/puppetlabs/puppetlabs-firewall/pull/944) ([IBBoard](https://github.com/IBBoard))
- \(IAC-987\) - Removal of inappropriate terminology [\#942](https://github.com/puppetlabs/puppetlabs-firewall/pull/942) ([david22swan](https://github.com/david22swan))

## [v2.5.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.5.0) (2020-07-28)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.4.0...v2.5.0)

### Added

- Add acceptance and unit test [\#931](https://github.com/puppetlabs/puppetlabs-firewall/pull/931) ([adrianiurca](https://github.com/adrianiurca))
- \[IAC-899\] - Add acceptance test for string_hex parameter [\#930](https://github.com/puppetlabs/puppetlabs-firewall/pull/930) ([adrianiurca](https://github.com/adrianiurca))
- Add support for NFLOG options to ip6tables [\#921](https://github.com/puppetlabs/puppetlabs-firewall/pull/921) ([frh](https://github.com/frh))

## [v2.4.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.4.0) (2020-05-13)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.3.0...v2.4.0)

### Added

- pdksync - \(IAC-973\) - Update travis/appveyor to run on new default branch main [\#933](https://github.com/puppetlabs/puppetlabs-firewall/pull/933) ([david22swan](https://github.com/david22swan))
- Add support for u32 module in iptables [\#917](https://github.com/puppetlabs/puppetlabs-firewall/pull/917) ([sanfrancrisko](https://github.com/sanfrancrisko))
- Add support for cgroup arg [\#916](https://github.com/puppetlabs/puppetlabs-firewall/pull/916) ([akerl-unpriv](https://github.com/akerl-unpriv))
- Extend LOG options [\#914](https://github.com/puppetlabs/puppetlabs-firewall/pull/914) ([martialblog](https://github.com/martialblog))

### Fixed

- \(MODULES-8543\) Remove nftables' backend warning from iptables_save outtput [\#911](https://github.com/puppetlabs/puppetlabs-firewall/pull/911) ([NITEMAN](https://github.com/NITEMAN))

## [v2.3.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.3.0) (2020-03-26)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.2.0...v2.3.0)

### Added

- Add iptables --hex-string support to firewall resource [\#907](https://github.com/puppetlabs/puppetlabs-firewall/pull/907) ([alexconrey](https://github.com/alexconrey))
- Add random_fully and rpfilter support [\#892](https://github.com/puppetlabs/puppetlabs-firewall/pull/892) ([treydock](https://github.com/treydock))
- \(MODULES-7800\) Add the ability to specify iptables connection tracking helpers. [\#890](https://github.com/puppetlabs/puppetlabs-firewall/pull/890) ([jimmyt86](https://github.com/jimmyt86))
- Support conntrack module [\#872](https://github.com/puppetlabs/puppetlabs-firewall/pull/872) ([haught](https://github.com/haught))

### Fixed

- \(maint\) Use fact.flush only when available [\#906](https://github.com/puppetlabs/puppetlabs-firewall/pull/906) ([Filipovici-Andrei](https://github.com/Filipovici-Andrei))
- \(MODULES-10358\) - Clarification added to Boolean validation checks [\#886](https://github.com/puppetlabs/puppetlabs-firewall/pull/886) ([david22swan](https://github.com/david22swan))
- Merge and remove duplicate README file, lint code snippets [\#878](https://github.com/puppetlabs/puppetlabs-firewall/pull/878) ([runejuhl](https://github.com/runejuhl))

## [v2.2.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.2.0) (2019-12-09)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.1.0...v2.2.0)

### Added

- Add support for Debian Unstable [\#876](https://github.com/puppetlabs/puppetlabs-firewall/pull/876) ([martialblog](https://github.com/martialblog))
- \(FM-8673\) - Support added for CentOS 8 [\#873](https://github.com/puppetlabs/puppetlabs-firewall/pull/873) ([david22swan](https://github.com/david22swan))
- FM-8400 - add debian10 support [\#862](https://github.com/puppetlabs/puppetlabs-firewall/pull/862) ([lionce](https://github.com/lionce))
- FM-8219 - Convert to litmus [\#855](https://github.com/puppetlabs/puppetlabs-firewall/pull/855) ([lionce](https://github.com/lionce))

### Fixed

- Change - Avoid puppet failures on windows nodes [\#874](https://github.com/puppetlabs/puppetlabs-firewall/pull/874) ([blackknight36](https://github.com/blackknight36))
- Fix parsing iptables rules with hyphen in comments [\#861](https://github.com/puppetlabs/puppetlabs-firewall/pull/861) ([Hexta](https://github.com/Hexta))

## [v2.1.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.1.0) (2019-09-24)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/v2.0.0...v2.1.0)

### Added

- \(MODULES-6136\) Add zone property of CT target. [\#852](https://github.com/puppetlabs/puppetlabs-firewall/pull/852) ([rwf14f](https://github.com/rwf14f))
- \(FM-8025\) Add RedHat 8 support [\#847](https://github.com/puppetlabs/puppetlabs-firewall/pull/847) ([eimlav](https://github.com/eimlav))

### Fixed

- MODULES-9801 - fix negated physdev [\#858](https://github.com/puppetlabs/puppetlabs-firewall/pull/858) ([lionce](https://github.com/lionce))

## [v2.0.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/v2.0.0) (2019-05-14)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.15.3...v2.0.0)

### Changed

- pdksync - \(MODULES-8444\) - Raise lower Puppet bound [\#841](https://github.com/puppetlabs/puppetlabs-firewall/pull/841) ([david22swan](https://github.com/david22swan))

### Added

- \(FM-7903\) - Implement Puppet Strings [\#838](https://github.com/puppetlabs/puppetlabs-firewall/pull/838) ([david22swan](https://github.com/david22swan))

### Fixed

- \(MODULES-8736\) IPtables support on RHEL8 [\#824](https://github.com/puppetlabs/puppetlabs-firewall/pull/824) ([EmilienM](https://github.com/EmilienM))

## [1.15.3](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.15.3) (2019-04-04)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.15.2...1.15.3)

### Fixed

- \(MODULES-8855\) Move ipvs test to exception spec [\#834](https://github.com/puppetlabs/puppetlabs-firewall/pull/834) ([eimlav](https://github.com/eimlav))
- \(MODULES-8842\) Fix ipvs not idempotent [\#833](https://github.com/puppetlabs/puppetlabs-firewall/pull/833) ([eimlav](https://github.com/eimlav))

## [1.15.2](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.15.2) (2019-03-26)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.15.1...1.15.2)

### Fixed

- \(MODULES-8615\) Fix rules with ipvs not parsing [\#828](https://github.com/puppetlabs/puppetlabs-firewall/pull/828) ([eimlav](https://github.com/eimlav))
- \(MODULES-7333\) - Change hashing method from MD5 to SHA256 [\#827](https://github.com/puppetlabs/puppetlabs-firewall/pull/827) ([david22swan](https://github.com/david22swan))
- \(MODULES-6547\) Fix existing rules with --dport not parsing [\#826](https://github.com/puppetlabs/puppetlabs-firewall/pull/826) ([eimlav](https://github.com/eimlav))
- \(MODULES-8648\) - Fix for failures on SLES 11 [\#816](https://github.com/puppetlabs/puppetlabs-firewall/pull/816) ([david22swan](https://github.com/david22swan))
- \(MODULES-8584\) Handle multiple escaped quotes in comments properly [\#815](https://github.com/puppetlabs/puppetlabs-firewall/pull/815) ([mateusz-gozdek-sociomantic](https://github.com/mateusz-gozdek-sociomantic))
- External control for iptables-persistent [\#795](https://github.com/puppetlabs/puppetlabs-firewall/pull/795) ([identw](https://github.com/identw))

## [1.15.1](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.15.1) (2019-02-01)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.15.0...1.15.1)

### Fixed

- \(DOC-3056\) Remove mention of rules ordering [\#809](https://github.com/puppetlabs/puppetlabs-firewall/pull/809) ([clairecadman](https://github.com/clairecadman))
- \(FM-7712\) - Remove Gentoo 1.0 testing/support for Firewall module [\#808](https://github.com/puppetlabs/puppetlabs-firewall/pull/808) ([david22swan](https://github.com/david22swan))
- \(MODULES-8360\) Fix IPv6 bug relating to Bugzilla 1015 [\#804](https://github.com/puppetlabs/puppetlabs-firewall/pull/804) ([alexharv074](https://github.com/alexharv074))

## [1.15.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.15.0) (2019-01-18)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.14.0...1.15.0)

### Added

- \(MODULES-8143\) - Add SLES 15 support [\#798](https://github.com/puppetlabs/puppetlabs-firewall/pull/798) ([eimlav](https://github.com/eimlav))
- Add nftables wrapper support for RHEL8 [\#794](https://github.com/puppetlabs/puppetlabs-firewall/pull/794) ([mwhahaha](https://github.com/mwhahaha))
- Changed regex for iniface and outiface to allow '@' in interface names [\#791](https://github.com/puppetlabs/puppetlabs-firewall/pull/791) ([GeorgeCox](https://github.com/GeorgeCox))
- \(MODULES-8214\) Handle src_type and dst_type as array [\#790](https://github.com/puppetlabs/puppetlabs-firewall/pull/790) ([mateusz-gozdek-sociomantic](https://github.com/mateusz-gozdek-sociomantic))
- \(MODULES-7990\) Merge multiple comments into one while parsing rules [\#789](https://github.com/puppetlabs/puppetlabs-firewall/pull/789) ([mateusz-gozdek-sociomantic](https://github.com/mateusz-gozdek-sociomantic))
- add -g flag handling in ip6tables.rb provider [\#788](https://github.com/puppetlabs/puppetlabs-firewall/pull/788) ([cestith](https://github.com/cestith))
- \(MODULES-7681\) Add support for bytecode property [\#771](https://github.com/puppetlabs/puppetlabs-firewall/pull/771) ([baurmatt](https://github.com/baurmatt))

### Fixed

- pdksync - \(FM-7655\) Fix rubygems-update for ruby \< 2.3 [\#801](https://github.com/puppetlabs/puppetlabs-firewall/pull/801) ([tphoney](https://github.com/tphoney))
- \(MODULES-6340\) - Address failure when name begins with 9XXX [\#796](https://github.com/puppetlabs/puppetlabs-firewall/pull/796) ([eimlav](https://github.com/eimlav))
- Amazon linux 2 changed its major version to 2 with the last update... [\#793](https://github.com/puppetlabs/puppetlabs-firewall/pull/793) ([erik-frontify](https://github.com/erik-frontify))

## [1.14.0](https://github.com/puppetlabs/puppetlabs-firewall/tree/1.14.0) (2018-09-27)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.13.0...1.14.0)

### Added

- pdksync - \(MODULES-6805\) metadata.json shows support for puppet 6 [\#782](https://github.com/puppetlabs/puppetlabs-firewall/pull/782) ([tphoney](https://github.com/tphoney))
- \(FM-7399\) - Prepare for changelog generator [\#780](https://github.com/puppetlabs/puppetlabs-firewall/pull/780) ([pmcmaw](https://github.com/pmcmaw))

## 1.13.0

[Full Changelog](https://github.com/puppetlabs/puppetlabs-firewall/compare/1.12.0...1.13.0)

### Added

- pdksync - \(MODULES-7705\) - Bumping stdlib dependency from \< 5.0.0 to \< 6.0.0 [\#775](https://github.com/puppetlabs/puppetlabs-firewall/pull/775) ([pmcmaw](https://github.com/pmcmaw))
- Add support for Amazon Linux 2 [\#768](https://github.com/puppetlabs/puppetlabs-firewall/pull/768) ([erik-frontify](https://github.com/erik-frontify))
- \(FM-7232\) - Update firewall to support Ubuntu 18.04 [\#767](https://github.com/puppetlabs/puppetlabs-firewall/pull/767) ([david22swan](https://github.com/david22swan))
- \[FM-7044\] Addition of Debian 9 support to firewall [\#765](https://github.com/puppetlabs/puppetlabs-firewall/pull/765) ([david22swan](https://github.com/david22swan))
- \[FM-6961\] Removal of unsupported OS from firewall [\#764](https://github.com/puppetlabs/puppetlabs-firewall/pull/764) ([david22swan](https://github.com/david22swan))

### Fixed

- \(MODULES-7627\) - Update README Limitations section [\#769](https://github.com/puppetlabs/puppetlabs-firewall/pull/769) ([eimlav](https://github.com/eimlav))
- Corrections to readme [\#766](https://github.com/puppetlabs/puppetlabs-firewall/pull/766) ([alexharv074](https://github.com/alexharv074))
- \(MODULES-6129\) negated option with address mask bugfix [\#756](https://github.com/puppetlabs/puppetlabs-firewall/pull/756) ([mirekys](https://github.com/mirekys))
- \(MODULES-2119\) iptables delete -p all exception [\#749](https://github.com/puppetlabs/puppetlabs-firewall/pull/749) ([mikkergimenez](https://github.com/mikkergimenez))

## 1.12.0

### Summary

This release uses the PDK convert functionality which in return makes the module PDK compliant. It also includes a roll up of maintenance changes.

#### Added

- PDK convert firewall ([MODULES-6455](https://tickets.puppet.com/browse/MODULES-6455)).
- Modulesync updates.

### Fixed

- Set correct `seluser` for CentOS/RHEL 5.x ([MODULES-6092](https://tickets.puppet.com/browse/MODULES-6092)).
- Fix error parsing rules with dashes in the chain name ([MODULES-6261](https://tickets.puppet.com/browse/MODULES-6261)).
- Changes to address additional Rubocop failures.
- (maint) Addressing puppet-lint doc warnings.

## Supported Release 1.11.0

### Summary

This release is to implement Rubocop changes within the module.

#### Added

- Rubocop has been implemented in the module.

### Changed

- Module sync was updated.
- Unparsable rules are now skipped with a warning.

## Supported Release 1.10.0

### Summary

This is a clean release prior to the module being run through rubocop.

#### Added

- Hashlimit module added.
- Firewall multi notes added.
- Gidd lookup now added.
- Simple sanity check added to hash parser rule.

### Changed

- Version requirement has been updated.
- An array is no lnger accepted for icmp types.
- UNTRACKED is now considered to be a valid state.
- Modulesync updates.
- ip6tables can be disabled.
- Readme format has been fixed.
- Fixes made to accomodate Puppet lint.
- Fix to regex i 'connlimit_spec.rb' and 'firewall_spec.rb'.
- General test fixes.
- Negated match sets know properly dealt with.
- Correct IP version for hostname resolution now chosen.
- Unmanaged rule regex regarding iptable has been fixed.

### Removed

- Ubuntu 10.04 and 12.04 removed.

## Supported Release 1.9.0

### Summary

This release includes several bugfixes and NFLOG support.

#### Added

- Support for NFLOG including the `NFLOG` jump target and four commandline options ([FM-4896](https://tickets.puppetlabs.com/browse/FM-4896))
- Support for the geoip module ([MODULES-4279](https://tickets.puppetlabs.com/browse/MODULES-4279))
- Management of the ebtables package

#### Fixed

- iptables parser fails with "Invalid address from IPAddr.new: -m" ([MODULES-4234](https://tickets.puppetlabs.com/browse/MODULES-4234))
- selinux context for iptables configuration
- Replace Puppet.version.to_f with Puppet::Util::Package.versioncmp ( [MODULES-4528](https://tickets.puppetlabs.com/browse/MODULES-4528))

## Supported Release 1.8.2

### Summary

This release includes numerous features and bugfixes, See below.

#### Bugfixes

- Fixing issue with double quotes being removed when part of the rule comment
- Add the --wait flag to the insert/update/delete iptables actions to prevent failures from occuring when iptables is running outside of puppet for iptables >= 1.4.20
- Fix iptables_version and ip6tables_version facts not returning the version

#### Features

- Support for multiple IP sets in a single rule
- Implement queue_bypass and queue_num parameters for NFQUEUE jump target
- Tighten SELinux permissions on persistent files
- RHEL7 SELinux support for puppet 3
- Manage ip6tables service for Redhat Family

## Supported Release 1.8.1

### Summary

This release documents an important issue with mcollective that may impact users of the firewall module. Workarounds are suggested as part of this advisory until mcollective can be patched.

#### Bugfixes

- Add mcollective rule-reversal known limitation

## Supported Release 1.8.0

### Summary

This release includes numerous features, bugfixes and other improvements including better handling when trying to delete already absent rules.

#### Features

- Added new 'pkg_ensure' parameter to allow the updating of the iptables package.
- Added new 'log_uid' property.
- Added 'sctp' to the 'proto' property.
- Added support for IPv6 NAT in Linux kernels >= 3.7.
- Added support for the security table.

#### Bugfixes

- (MODULES-2783) Replaced hardcoded iptables service references with $service_name variable.
- (MODULES-1341) Recover when deleting absent rules.
- (MODULES-3032) Facter flush is called to clear Facter cache get up to date value for ':iptables_persistent_version'.
- (MODULES-2159) Fixed idempotency issue when using connlimit.
- Fixed the handling of chain names that contain '-f'.

#### Improvements

- Numerous unit and acceptance test improvements.
- Improved handling/use of the '$::iptables_persistent_version' custom fact.
- Better handling of operating systems that use SELinux.

## Supported Release 1.7.2

### Summary

Small release for support of newer PE versions. This increments the version of PE in the metadata.json file.

## 2015-08-25 - Supported Release 1.7.1

### Summary

This is a bugfix release to deprecate the port parameter. Using the unspecific 'port' parameter can lead to firewall rules that are unexpectedly too lax. It is recommended to always use the specific dport and sport parameters to avoid this ambiguity.

#### Bugfixes

- Deprecate the port parameter

## 2015-07-28 - Supported Release 1.7.0

### Summary

This release includes numerous features, bugfixes and other improvements including Puppet 4 & PE 2015.2 support as well as ClusterIP and DSCP jump target support.

#### Features

- Puppet 4 and PE 2015.2 official support
- ClusterIP jump target (including options) now supported
- DSCP jump target (including options) now supported
- SLES 10 now compatible (but not supported)

#### Bugfixes

- (MODULES-1967) Parse escape sequences from iptables
- (MODULES-1592) Allow src_type and dst_type prefixed with '!' to pass validation
- (MODULES-2186) - iptables rules with -A in comment now supported
- (MODULES-1976) Revise rule name validation for ruby 1.9
- Fix installation hang on Debian Jessie
- Fix for physdev idempotency on EL5

#### Improvements

- Documentation improvements
- Enforce the seluser on selinux systems
- All the relevent services are now autorequired by the firewall and firewallchain types
- Replace Facter.fact().value() calls with Facter.value() to support Facter 3

## 2015-05-19 - Supported Release 1.6.0

### Summary

This release includes support for TEE, MSS, the time ipt module, Debian 8 support, and a number of test fixes and other improvements.

#### Features

- Add TEE support
- Add MSS support (including clamp-mss-to-pmtu support)
- Add support for the time ipt module (-m time)
- Add support for Debian 8
- Add support for ICMPv6 types 'neighbour-{solicitation,advertisement}'
- Add support for ICMPv6 type 'too-big'
- Add support for new 'match_mark' property
- Added 'ipv4' and 'ipv6' options to 'proto' property

#### Bugfixes

- Fix for Systemd-based OSes where systemd needs restarted before being able to pick up new services (MODULES-1984)
- Arch Linux package management fix

## 2015-03-31 - Supported Release 1.5.0

### Summary

This release includes physdev_is_bridged support, checksum_fill support, basic Gentoo compatibility, and a number of test fixes and improvements.

#### Features

- Add `physdev_is_bridged` support
- Add `checksum_fill` support
- Add basic Gentoo compatibility (unsupported)

#### Bugfixes

- Implementation for resource map munging to allow a single ipt module to be used multiple times in a single rule on older versions of iptables (MODULES-1808)
- Test fixes

## 2015-01-27 - Supported Release 1.4.0

### Summary

This release includes physdev support, the ability to look up usernames from uuid, and a number of bugfixes

#### Features

- Add `netmap` feature
- Add `physdev` support
- Add ability to look up username from uuid (MODULES-753, MODULES-1688)

#### Bugfixes

- Sync iptables/ip6tables providers (MODULES-1612)
- Fix package names for Amazon and Ubuntu 14.10 (MODULES-1029)
- Fix overly aggressive gsub when `ensure => absent` (MODULES-1453)
- Unable to parse `-m (tcp|udp)` rules (MODULES-1552)
- Fix ip6tables provider when `iptables-ipv6` package isn't installed for EL6 (MODULES-633)
- Test fixes

## 2014-12-16 - Supported Release 1.3.0

### Summary

This release includes a number of bugfixes and features, including fixing `tcp_flags` support, and added support for interface aliases, negation for iniface and outiface, and extra configurability for packages and service names.

#### Features

- Add support for interface aliases (eth0:0) (MODULES-1469)
- Add negation for iniface, outiface (MODULES-1470)
- Make package and service names configurable (MODULES-1309)

#### Bugfixes

- Fix test regexes for EL5 (MODULES-1565)
- Fix `tcp_flags` support for ip6tables (MODULES-556)
- Don't arbitrarily limit `set_mark` for certain chains

## 2014-11-04 - Supported Release 1.2.0

### Summary

This release has a number of new features and bugfixes, including rule inversion, future parser support, improved EL7 support, and the ability to purge ip6tables rules.

#### Features

- Documentation updates!
- Test updates!
- Add ipset support
- Enable rule inversion
- Future parser support
- Improved support for EL7
- Support netfilter-persistent
- Add support for statistics module
- Add support for mac address source rules
- Add cbt protocol

#### Bugfixes

- Incorrect use of `source => :iptables` in the ip6tables provider was making it impossible to purge ip6tables rules (MODULES-41)
- Don't require `toports` when `jump => 'REDIRECT'` (MODULES-1086)
- Don't limit which chains iniface and outiface parameters can be used in
- Don't fail on rules added with ipsec/strongswan (MODULES-796)

## 2014-07-08 - Supported Release 1.1.3

### Summary

This is a supported release with test coverage enhancements.

#### Bugfixes

- Confine to supported kernels

## 2014-06-04 - Release 1.1.2

### Summary

This is a release of the code previously released as 1.1.1, with updated metadata.

## 2014-05-16 Release 1.1.1

### Summary

This release reverts the alphabetical ordering of 1.1.0. We found this caused
a regression in the Openstack modules so in the interest of safety we have
removed this for now.

## 2014-05-13 Release 1.1.0

### Summary

This release has a significant change from previous releases; we now apply the
firewall resources alphabetically by default, removing the need to create pre
and post classes just to enforce ordering. It only effects default ordering
and further information can be found in the README about this. Please test
this in development before rolling into production out of an abundance of
caution.

We've also added `mask` which is required for --recent in recent (no pun
intended) versions of iptables, as well as connlimit and connmark. This
release has been validated against Ubuntu 14.04 and RHEL7 and should be fully
working on those platforms.

#### Features

- Apply firewall resources alphabetically.
- Add support for connlimit and connmark.
- Add `mask` as a parameter. (Used exclusively with the recent parameter).

#### Bugfixes

- Add systemd support for RHEL7.
- Replace &&'s with the correct and in manifests.
- Fix tests on Trusty and RHEL7
- Fix for Fedora Rawhide.
- Fix boolean flag tests.
- Fix DNAT->SNAT typo in an error message.

#### Known Bugs

- For Oracle, the `owner` and `socket` parameters require a workaround to function. Please see the Limitations section of the README.

## 2014-03-04 Supported Release 1.0.2

### Summary

This is a supported release. This release removes a testing symlink that can
cause trouble on systems where /var is on a seperate filesystem from the
modulepath.

#### Features

#### Bugfixes

#### Known Bugs

- For Oracle, the `owner` and `socket` parameters require a workaround to function. Please see the Limitations section of the README.

### Supported release - 2014-03-04 1.0.1

#### Summary

An important bugfix was made to the offset calculation for unmanaged rules
to handle rules with 9000+ in the name.

#### Features

#### Bugfixes

- Offset calculations assumed unmanaged rules were numbered 9000+.
- Gracefully fail to manage ip6tables on iptables 1.3.x

#### Known Bugs

- For Oracle, the `owner` and `socket` parameters require a workaround to function. Please see the Limitations section of the README.

---

### 1.0.0 - 2014-02-11

No changes, just renumbering to 1.0.0.

---

### 0.5.0 - 2014-02-10

##### Summary:

This is a bigger release that brings in "recent" connection limiting (think
"port knocking"), firewall chain purging on a per-chain/per-table basis, and
support for a few other use cases. This release also fixes a major bug which
could cause modifications to the wrong rules when unmanaged rules are present.

##### New Features:

- Add "recent" limiting via parameters `rdest`, `reap`, `recent`, `rhitcount`,
  `rname`, `rseconds`, `rsource`, and `rttl`
- Add negation support for source and destination
- Add per-chain/table purging support to `firewallchain`
- IPv4 specific
  - Add random port forwarding support
  - Add ipsec policy matching via `ipsec_dir` and `ipsec_policy`
- IPv6 specific
  - Add support for hop limiting via `hop_limit` parameter
  - Add fragmentation matchers via `ishasmorefrags`, `islastfrag`, and `isfirstfrag`
  - Add support for conntrack stateful firewall matching via `ctstate`

##### Bugfixes:

- Boolean fixups allowing false values
- Better detection of unmanaged rules
- Fix multiport rule detection
- Fix sport/dport rule detection
- Make INPUT, OUTPUT, and FORWARD not autorequired for firewall chain filter
- Allow INPUT with the nat table
- Fix `src_range` & `dst_range` order detection
- Documentation clarifications
- Fixes to spec tests

---

### 0.4.2 - 2013-09-10

Another attempt to fix the packaging issue. We think we understand exactly
what is failing and this should work properly for the first time.

---

### 0.4.1 - 2013-08-09

Bugfix release to fix a packaging issue that may have caused puppet module
install commands to fail.

---

### 0.4.0 - 2013-07-11

This release adds support for address type, src/dest ip ranges, and adds
additional testing and bugfixes.

#### Features

- Add `src_type` and `dst_type` attributes (Nick Stenning)
- Add `src_range` and `dst_range` attributes (Lei Zhang)
- Add SL and SLC operatingsystems as supported (Steve Traylen)

#### Bugfixes

- Fix parser for bursts other than 5 (Chris Rutter)
- Fix parser for -f in --comment (Georg Koester)
- Add doc headers to class files (Dan Carley)
- Fix lint warnings/errors (Wolf Noble)

---

### 0.3.1 - 2013/6/10

This minor release provides some bugfixes and additional tests.

#### Changes

- Update tests for rspec-system-puppet 2 (Ken Barber)
- Update rspec-system tests for rspec-system-puppet 1.5 (Ken Barber)
- Ensure all services have 'hasstatus => true' for Puppet 2.6 (Ken Barber)
- Accept pre-existing rule with invalid name (Joe Julian)
- Swap log_prefix and log_level order to match the way it's saved (Ken Barber)
- Fix log test to replicate bug #182 (Ken Barber)
- Split argments while maintaining quoted strings (Joe Julian)
- Add more log param tests (Ken Barber)
- Add extra tests for logging parameters (Ken Barber)
- Clarify OS support (Ken Barber)

---

### 0.3.0 - 2013/4/25

This release introduces support for Arch Linux and extends support for Fedora 15 and up. There are also lots of bugs fixed and improved testing to prevent regressions.

##### Changes

- Fix error reporting for insane hostnames (Tomas Doran)
- Support systemd on Fedora 15 and up (Eduardo Gutierrez)
- Move examples to docs (Ken Barber)
- Add support for Arch Linux platform (Ingmar Steen)
- Add match rule for fragments (Georg Koester)
- Fix boolean rules being recognized as changed (Georg Koester)
- Same rules now get deleted (Anastasis Andronidis)
- Socket params test (Ken Barber)
- Ensure parameter can disable firewall (Marc Tardif)

---

### 0.2.1 - 2012/3/13

This maintenance release introduces the new README layout, and fixes a bug with iptables_persistent_version.

##### Changes

- (GH-139) Throw away STDERR from dpkg-query in Fact
- Update README to be consistent with module documentation template
- Fix failing spec tests due to dpkg change in iptables_persistent_version

---

### 0.2.0 - 2012/3/3

This release introduces automatic persistence, removing the need for the previous manual dependency requirement for persistent the running rules to the OS persistence file.

Previously you would have required the following in your site.pp (or some other global location):

    # Always persist firewall rules
    exec { 'persist-firewall':
      command     => $operatingsystem ? {
        'debian'          => '/sbin/iptables-save > /etc/iptables/rules.v4',
        /(RedHat|CentOS)/ => '/sbin/iptables-save > /etc/sysconfig/iptables',
      },
      refreshonly => true,
    }
    Firewall {
      notify  => Exec['persist-firewall'],
      before  => Class['my_fw::post'],
      require => Class['my_fw::pre'],
    }
    Firewallchain {
      notify  => Exec['persist-firewall'],
    }
    resources { "firewall":
      purge => true
    }

You only need:

    class { 'firewall': }
    Firewall {
      before  => Class['my_fw::post'],
      require => Class['my_fw::pre'],
    }

To install pre-requisites and to create dependencies on your pre & post rules. Consult the README for more information.

##### Changes

- Firewall class manifests (Dan Carley)
- Firewall and firewallchain persistence (Dan Carley)
- (GH-134) Autorequire iptables related packages (Dan Carley)
- Typo in #persist_iptables OS normalisation (Dan Carley)
- Tests for #persist_iptables (Dan Carley)
- (GH-129) Replace errant return in autoreq block (Dan Carley)

---

### 0.1.1 - 2012/2/28

This release primarily fixes changing parameters in 3.x

##### Changes

- (GH-128) Change method_missing usage to define_method for 3.x compatibility
- Update travis.yml gem specifications to actually test 2.6
- Change source in Gemfile to use a specific URL for Ruby 2.0.0 compatibility

---

### 0.1.0 - 2012/2/24

This release is somewhat belated, so no summary as there are far too many changes this time around. Hopefully we won't fall this far behind again :-).

##### Changes

- Add support for MARK target and set-mark property (Johan Huysmans)
- Fix broken call to super for ruby-1.9.2 in munge (Ken Barber)
- simple fix of the error message for allowed values of the jump property (Daniel Black)
- Adding OSPF(v3) protocol to puppetlabs-firewall (Arnoud Vermeer)
- Display multi-value: port, sport, dport and state command seperated (Daniel Black)
- Require jump=>LOG for log params (Daniel Black)
- Reject and document icmp => "any" (Dan Carley)
- add firewallchain type and iptables_chain provider (Daniel Black)
- Various fixes for firewallchain resource (Ken Barber)
- Modify firewallchain name to be chain:table:protocol (Ken Barber)
- Fix allvalidchain iteration (Ken Barber)
- Firewall autorequire Firewallchains (Dan Carley)
- Tests and docstring for chain autorequire (Dan Carley)
- Fix README so setup instructions actually work (Ken Barber)
- Support vlan interfaces (interface containing ".") (Johan Huysmans)
- Add tests for VLAN support for iniface/outiface (Ken Barber)
- Add the table when deleting rules (Johan Huysmans)
- Fix tests since we are now prefixing -t)
- Changed 'jump' to 'action', commands to lower case (Jason Short)
- Support interface names containing "+" (Simon Deziel)
- Fix for when iptables-save spews out "FATAL" errors (Sharif Nassar)
- Fix for incorrect limit command arguments for ip6tables provider (Michael Hsu)
- Document Util::Firewall.host_to_ip (Dan Carley)
- Nullify addresses with zero prefixlen (Dan Carley)
- Add support for --tcp-flags (Thomas Vander Stichele)
- Make tcp_flags support a feature (Ken Barber)
- OUTPUT is a valid chain for the mangle table (Adam Gibbins)
- Enable travis-ci support (Ken Barber)
- Convert an existing test to CIDR (Dan Carley)
- Normalise iptables-save to CIDR (Dan Carley)
- be clearer about what distributions we support (Ken Barber)
- add gre protocol to list of acceptable protocols (Jason Hancock)
- Added pkttype property (Ashley Penney)
- Fix mark to not repeat rules with iptables 1.4.1+ (Sharif Nassar)
- Stub iptables_version for now so tests run on non-Linux hosts (Ken Barber)
- Stub iptables facts for set_mark tests (Dan Carley)
- Update formatting of README to meet Puppet Labs best practices (Will Hopper)
- Support for ICMP6 type code resolutions (Dan Carley)
- Insert order hash included chains from different tables (Ken Barber)
- rspec 2.11 compatibility (Jonathan Boyett)
- Add missing class declaration in README (sfozz)
- array_matching is contraindicated (Sharif Nassar)
- Convert port Fixnum into strings (Sharif Nassar)
- Update test framework to the modern age (Ken Barber)
- working with ip6tables support (wuwx)
- Remove gemfile.lock and add to gitignore (William Van Hevelingen)
- Update travis and gemfile to be like stdlib travis files (William Van Hevelingen)
- Add support for -m socket option (Ken Barber)
- Add support for single --sport and --dport parsing (Ken Barber)
- Fix tests for Ruby 1.9.3 from 3e13bf3 (Dan Carley)
- Mock Resolv.getaddress in #host_to_ip (Dan Carley)
- Update docs for source and dest - they are not arrays (Ken Barber)

---

### 0.0.4 - 2011/12/05

This release adds two new parameters, 'uid' and 'gid'. As a part of the owner module, these params allow you to specify a uid, username, gid, or group got a match:

    firewall { '497 match uid':
      port => '123',
      proto => 'mangle',
      chain => 'OUTPUT',
      action => 'drop'
      uid => '123'
    }

This release also adds value munging for the 'log_level', 'source', and 'destination' parameters. The 'source' and 'destination' now support hostnames:

    firewall { '498 accept from puppetlabs.com':
      port => '123',
      proto => 'tcp',
      source => 'puppetlabs.com',
      action => 'accept'
    }

The 'log_level' parameter now supports using log level names, such as 'warn', 'debug', and 'panic':

    firewall { '499 logging':
      port => '123',
      proto => 'udp',
      log_level => 'debug',
      action => 'drop'
    }

Additional changes include iptables and ip6tables version facts, general whitespace cleanup, and adding additional unit tests.

##### Changes

- (#10957) add iptables_version and ip6tables_version facts
- (#11093) Improve log_level property so it converts names to numbers
- (#10723) Munge hostnames and IPs to IPs with CIDR
- (#10718) Add owner-match support
- (#10997) Add fixtures for ipencap
- (#11034) Whitespace cleanup
- (#10690) add port property support to ip6tables

---

### 0.0.3 - 2011/11/12

This release introduces a new parameter 'port' which allows you to set both
source and destination ports for a match:

    firewall { "500 allow NTP requests":
      port => "123",
      proto => "udp",
      action => "accept",
    }

We also have the limit parameter finally working:

    firewall { "500 limit HTTP requests":
      dport => 80,
      proto => tcp,
      limit => "60/sec",
      burst => 30,
      action => accept,
    }

State ordering has been fixed now, and more characters are allowed in the
namevar:

- Alphabetical
- Numbers
- Punctuation
- Whitespace

##### Changes

- (#10693) Ensure -m limit is added for iptables when using 'limit' param
- (#10690) Create new port property
- (#10700) allow additional characters in comment string
- (#9082) Sort iptables --state option values internally to keep it consistent across runs
- (#10324) Remove extraneous whitespace from iptables rule line in spec tests

---

### 0.0.2 - 2011/10/26

This is largely a maintanence and cleanup release, but includes the ability to
specify ranges of ports in the sport/dport parameter:

    firewall { "500 allow port range":
      dport => ["3000-3030","5000-5050"],
      sport => ["1024-65535"],
      action => "accept",
    }

##### Changes

- (#10295) Work around bug #4248 whereby the puppet/util paths are not being loaded correctly on the puppet server
- (#10002) Change to dport and sport to handle ranges, and fix handling of name to name to port
- (#10263) Fix tests on Puppet 2.6.x
- (#10163) Cleanup some of the inline documentation and README file to align with general forge usage

---

### 0.0.1 - 2011/10/18

Initial release.

##### Changes

- (#9362) Create action property and perform transformation for accept, drop, reject value for iptables jump parameter
- (#10088) Provide a customised version of CONTRIBUTING.md
- (#10026) Re-arrange provider and type spec files to align with Puppet
- (#10026) Add aliases for test,specs,tests to Rakefile and provide -T as default
- (#9439) fix parsing and deleting existing rules
- (#9583) Fix provider detection for gentoo and unsupported linuxes for the iptables provider
- (#9576) Stub provider so it works properly outside of Linux
- (#9576) Align spec framework with Puppet core
- and lots of other earlier development tasks ...


\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
