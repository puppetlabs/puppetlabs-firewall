require 'spec_helper_acceptance'

describe 'firewall basics', docker: true do
  before :all do
    iptables_flush_all_tables
    ip6tables_flush_all_tables
  end

  describe 'name' do
    context 'when invalid ordering range specified' do
      pp = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '001 - test': ensure => present }
          firewall { '9946 test': ensure => present }
      PUPPETCODE
      it 'fails' do
        apply_manifest(pp, expect_failures: true) do |r|
          expect(r.stderr).to match(%r{Rule sorting error})
        end
      end
    end
  end

  describe 'ensure' do
    context 'when present' do
      pp4 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '555 - test':
            ensure => present,
            proto  => tcp,
            port   => '555',
            action => accept,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp4, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -p tcp -m multiport --ports 555 -m comment --comment "555 - test" -j ACCEPT})
        end
      end
    end

    context 'when absent' do
      pp5 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '555 - test':
            ensure => absent,
            proto  => tcp,
            port   => '555',
            action => accept,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp5, catch_failures: true)
      end

      it 'does not contain the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m multiport --ports 555 -m comment --comment "555 - test" -j ACCEPT})
        end
      end
    end
  end

  describe 'sport' do
    context 'when invalid ports' do
      pp19 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '560 - test':
            proto  => tcp,
            sport  => '9999560-561',
            action => accept,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp19, expect_failures: true) do |r|
          expect(r.stderr).to match(%r{invalid port\/service `9999560' specified})
        end
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m multiport --sports 9999560-561 -m comment --comment "560 - test" -j ACCEPT})
        end
      end
    end
  end

  describe 'dport' do
    context 'when invalid ports' do
      pp22 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '561 - test':
            proto  => tcp,
            dport  => '9999561-562',
            action => accept,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp22, expect_failures: true) do |r|
          expect(r.stderr).to match(%r{invalid port\/service `9999561' specified})
        end
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m multiport --dports 9999561-562 -m comment --comment "560 - test" -j ACCEPT})
        end
      end
    end
  end

  describe 'hashlimit' do
    context 'when hashlimit_above' do
      pp1 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '800 - hashlimit_above test':
            chain                       => 'INPUT',
            proto                       => 'tcp',
            hashlimit_name              => 'above',
            hashlimit_above             => '526/sec',
            hashlimit_htable_gcinterval => '10',
            hashlimit_mode              => 'srcip,dstip',
            action                      => accept,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp1, catch_failures: true)
        apply_manifest(pp1, catch_changes: do_catch_changes)
      end

      regex_array = [%r{-A INPUT}, %r{-p tcp}, %r{--hashlimit-above 526\/sec}, %r{--hashlimit-mode srcip,dstip},
                     %r{--hashlimit-name above}, %r{--hashlimit-htable-gcinterval 10}, %r{-j ACCEPT}]
      it 'contains the rule' do
        shell('iptables-save') do |r|
          regex_array.each do |regex|
            expect(r.stdout).to match(regex)
          end
        end
      end
    end

    context 'when hashlimit_above_ip6' do
      pp2 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '801 - hashlimit_above test ipv6':
            chain                       => 'INPUT',
            provider                    => 'ip6tables',
            proto                       => 'tcp',
            hashlimit_name              => 'above-ip6',
            hashlimit_above             => '526/sec',
            hashlimit_htable_gcinterval => '10',
            hashlimit_mode              => 'srcip,dstip',
            action                      => accept,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp2, catch_failures: true)
        apply_manifest(pp2, catch_changes: do_catch_changes)
      end

      regex_array = [%r{-A INPUT}, %r{-p tcp}, %r{--hashlimit-above 526\/sec}, %r{--hashlimit-mode srcip,dstip},
                     %r{--hashlimit-name above-ip6}, %r{--hashlimit-htable-gcinterval 10}, %r{-j ACCEPT}]
      it 'contains the rule' do
        shell('ip6tables-save') do |r|
          regex_array.each do |regex|
            expect(r.stdout).to match(regex)
          end
        end
      end
    end

    context 'when hashlimit_upto' do
      pp3 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '802 - hashlimit_upto test':
            chain                   => 'INPUT',
            hashlimit_name          => 'upto',
            hashlimit_upto          => '16/sec',
            hashlimit_burst         => '640',
            hashlimit_htable_size   => '1310000',
            hashlimit_htable_max    => '320000',
            hashlimit_htable_expire => '36000000',
            action                  => accept,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp3, catch_failures: true)
        apply_manifest(pp3, catch_changes: do_catch_changes)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -p tcp -m hashlimit --hashlimit-upto 16\/sec --hashlimit-burst 640 --hashlimit-name upto --hashlimit-htable-size 1310000 --hashlimit-htable-max 320000 --hashlimit-htable-expire 36000000 -m comment --comment "802 - hashlimit_upto test" -j ACCEPT}) # rubocop:disable Metrics/LineLength : Cannot reduce line to required length
        end
      end
    end
  end

  describe 'firewall inverting' do
    context 'when inverting partial array rules' do
      pp2 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '603 drop 80,443 traffic':
            chain     => 'INPUT',
            action    => 'drop',
            proto     => 'tcp',
            sport     => ['! http', '443'],
          }
      PUPPETCODE
      it 'raises a failure' do
        apply_manifest(pp2, expect_failures: true) do |r|
          expect(r.stderr).to match(%r{is not prefixed})
        end
      end
    end
  end

  describe 'port' do
    context 'when invalid ports' do
      pp25 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '562 - test':
            proto  => tcp,
            port  => '9999562-563',
            action => accept,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp25, expect_failures: true) do |r|
          expect(r.stderr).to match(%r{invalid port\/service `9999562' specified})
        end
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m multiport --ports 9999562-563 -m comment --comment "562 - test" -j ACCEPT})
        end
      end
    end
  end

  ['dst_type', 'src_type'].each do |type|
    describe type.to_s do
      context 'when LOCAL --limit-iface-in', unless: (os[:family] == 'redhat' && os[:release].start_with?('5')) do
        pp97 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '613 - test':
              proto   => tcp,
              action  => accept,
              #{type} => 'LOCAL --limit-iface-in',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp97, catch_failures: true)
        end

        it 'contains the rule' do
          shell('iptables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p tcp -m addrtype\s.*\sLOCAL --limit-iface-in -m comment --comment "613 - test" -j ACCEPT})
          end
        end
      end

      context 'when LOCAL --limit-iface-in fail', if: (os[:family] == 'redhat' && os[:release].start_with?('5')) do
        pp98 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '614 - test':
              proto   => tcp,
              action  => accept,
              #{type} => 'LOCAL --limit-iface-in',
            }
        PUPPETCODE
        it 'fails' do
          apply_manifest(pp98, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{--limit-iface-in and --limit-iface-out are available from iptables version})
          end
        end

        it 'does not contain the rule' do
          shell('iptables-save') do |r|
            expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m addrtype\s.*\sLOCAL --limit-iface-in -m comment --comment "614 - test" -j ACCEPT})
          end
        end
      end

      context 'when duplicated LOCAL', unless: (os[:family] == 'redhat' && os[:release].start_with?('5')) do
        pp99 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '615 - test':
              proto   => tcp,
              action  => accept,
              #{type} => ['LOCAL', 'LOCAL'],
            }
        PUPPETCODE
        it 'fails' do
          apply_manifest(pp99, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{#{type} elements must be unique})
          end
        end

        it 'does not contain the rule' do
          shell('iptables-save') do |r|
            expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m addrtype --#{type.tr('_', '-')} LOCAL -m addrtype --#{type.tr('_', '-')} LOCAL -m comment --comment "615 - test" -j ACCEPT})
          end
        end
      end

      context 'when multiple addrtype', unless: (os[:family] == 'redhat' && os[:release].start_with?('5')) do
        pp100 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '616 - test':
              proto   => tcp,
              action  => accept,
              #{type} => ['LOCAL', '! LOCAL'],
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp100, catch_failures: true)
        end

        it 'contains the rule' do
          shell('iptables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p tcp -m addrtype --#{type.tr('_', '-')} LOCAL -m addrtype ! --#{type.tr('_', '-')} LOCAL -m comment --comment "616 - test" -j ACCEPT})
          end
        end
      end

      context 'when multiple addrtype fail', if: (os[:family] == 'redhat' && os[:release].start_with?('5')) do
        pp101 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '616 - test':
              proto   => tcp,
              action  => accept,
              #{type} => ['LOCAL', '! LOCAL'],
            }
        PUPPETCODE
        it 'fails' do
          apply_manifest(pp101, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{Multiple #{type} elements are available from iptables version})
          end
        end

        it 'does not contain the rule' do
          shell('iptables-save') do |r|
            expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m addrtype --#{type.tr('_', '-')} LOCAL -m addrtype ! --#{type.tr('_', '-')} LOCAL -m comment --comment "616 - test" -j ACCEPT})
          end
        end
      end
    end
  end

  describe 'table' do
    context 'when mangle' do
      pp31 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '566 - test':
            proto  => tcp,
            action => accept,
            table  => 'mangle',
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp31, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save -t mangle') do |r|
          expect(r.stdout).to match(%r{-A INPUT -p tcp -m comment --comment "566 - test" -j ACCEPT})
        end
      end
    end
    context 'when nat' do
      pp32 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '566 - test2':
            proto  => tcp,
            action => accept,
            table  => 'nat',
            chain  => 'OUTPUT',
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp32, catch_failures: true)
      end

      it 'does not contain the rule' do
        shell('iptables-save -t nat') do |r|
          expect(r.stdout).to match(%r{-A OUTPUT -p tcp -m comment --comment "566 - test2" -j ACCEPT})
        end
      end
    end
  end

  describe 'jump' do
    after :all do
      iptables_flush_all_tables
    end

    context 'when MARK' do
      pp33 = <<-PUPPETCODE
          class { '::firewall': }
          firewallchain { 'TEST:filter:IPv4':
            ensure => present,
          }
          firewall { '567 - test':
            proto  => tcp,
            chain  => 'INPUT',
            jump  => 'TEST',
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp33, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -p tcp -m comment --comment "567 - test" -j TEST})
        end
      end
    end
  end

  unless (os[:family] == 'redhat' && os[:release].start_with?('5')) || os[:family] == 'sles'
    describe 'checksum_fill' do
      context 'when virbr' do
        pp38 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '576 - test':
              proto  => udp,
              table  => 'mangle',
              outiface => 'virbr0',
              chain  => 'POSTROUTING',
              dport => '68',
              jump  => 'CHECKSUM',
              checksum_fill => true,
              provider => iptables,
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp38, catch_failures: true)
        end

        it 'contains the rule' do
          shell('iptables-save -t mangle') do |r|
            expect(r.stdout).to match(%r{-A POSTROUTING -o virbr0 -p udp -m multiport --dports 68 -m comment --comment "576 - test" -j CHECKSUM --checksum-fill})
          end
        end
      end
    end
  end

  # RHEL5 does not support --random
  unless os[:family] == 'redhat' && os[:release].start_with?('5')
    describe 'random' do
      context 'when 192.168.1.1' do
        pp40 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '570 - test 2':
              proto  => all,
              table  => 'nat',
              chain  => 'POSTROUTING',
              jump   => 'MASQUERADE',
              source => '172.30.0.0/16',
              random => true
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp40, catch_failures: true)
          apply_manifest(pp40, catch_changes: do_catch_changes)
        end

        it 'contains the rule' do
          shell('iptables-save -t nat') do |r|
            expect(r.stdout).to match(%r{-A POSTROUTING -s 172\.30\.0\.0\/16 -m comment --comment "570 - test 2" -j MASQUERADE --random})
          end
        end
      end
    end
  end

  ['dst_type', 'src_type'].each do |type|
    describe type.to_s do
      context 'when LOCAL --limit-iface-in', unless: (os[:family] == 'redhat' && os[:release].start_with?('5')
                                                     ) do
        pp102 = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '617 - test':
                proto   => tcp,
                action  => accept,
                #{type} => 'LOCAL --limit-iface-in',
              }
          PUPPETCODE
        it 'applies' do
          apply_manifest(pp102, catch_failures: true)
        end

        it 'contains the rule' do
          shell('iptables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p tcp -m addrtype\s.*\sLOCAL --limit-iface-in -m comment --comment "617 - test" -j ACCEPT})
          end
        end
      end

      context 'when LOCAL --limit-iface-in fail', if: (os[:family] == 'redhat' && os[:release].start_with?('5')
                                                      ) do
        pp103 = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '618 - test':
                proto   => tcp,
                action  => accept,
                #{type} => 'LOCAL --limit-iface-in',
              }
          PUPPETCODE
        it 'fails' do
          apply_manifest(pp103, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{--limit-iface-in and --limit-iface-out are available from iptables version})
          end
        end

        it 'does not contain the rule' do
          shell('iptables-save') do |r|
            expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m addrtype\s.*\sLOCAL --limit-iface-in -m comment --comment "618 - test" -j ACCEPT})
          end
        end
      end
    end
  end

  # iptables version 1.3.5 does not support masks on MARK rules
  unless os[:family] == 'redhat' && os[:release].start_with?('5')
    describe 'set_mark' do
      context 'when 0x3e8/0xffffffff' do
        pp73 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '580 - test':
              ensure => present,
              chain => 'OUTPUT',
              proto => tcp,
              port   => '580',
              jump => 'MARK',
              table => 'mangle',
              set_mark => '0x3e8/0xffffffff',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp73, catch_failures: true)
        end

        it 'contains the rule' do
          shell('iptables-save -t mangle') do |r|
            expect(r.stdout).to match(%r{-A OUTPUT -p tcp -m multiport --ports 580 -m comment --comment "580 - test" -j MARK --set-xmark 0x3e8\/0xffffffff})
          end
        end
      end
    end
  end

  # RHEL5/SLES does not support -m socket
  describe 'socket', unless: (os[:family] == 'redhat' && os[:release].start_with?('5')) || (os[:family] == 'sles') do
    context 'when true' do
      pp78 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '585 - test':
            ensure => present,
            proto => tcp,
            port   => '585',
            action => accept,
            chain  => 'PREROUTING',
            table  => 'nat',
            socket => true,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp78, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save -t nat') do |r|
          expect(r.stdout).to match(%r{-A PREROUTING -p tcp -m multiport --ports 585 -m socket -m comment --comment "585 - test" -j ACCEPT})
        end
      end
    end

    context 'when false' do
      pp79 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '586 - test':
            ensure => present,
            proto => tcp,
            port   => '586',
            action => accept,
            chain  => 'PREROUTING',
            table  => 'nat',
            socket => false,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp79, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save -t nat') do |r|
          expect(r.stdout).to match(%r{-A PREROUTING -p tcp -m multiport --ports 586 -m comment --comment "586 - test" -j ACCEPT})
        end
      end
    end
  end

  describe 'recent' do
    context 'when set' do
      pp84 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '597 - test':
            ensure       => 'present',
            chain        => 'INPUT',
            destination  => '30.0.0.0/8',
            proto        => 'all',
            table        => 'filter',
            recent       => 'set',
            rdest        => true,
            rname        => 'list1',
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp84, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          # Mask added as of Ubuntu 14.04.
          expect(r.stdout).to match(%r{-A INPUT -d 30.0.0.0\/(8|255\.0\.0\.0) -m recent --set --name list1 (--mask 255.255.255.255 )?--rdest -m comment --comment "597 - test"})
        end
      end
    end

    context 'when rcheck' do
      pp85 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '598 - test':
            ensure       => 'present',
            chain        => 'INPUT',
            destination  => '30.0.0.0/8',
            proto        => 'all',
            table        => 'filter',
            recent       => 'rcheck',
            rsource      => true,
            rname        => 'list1',
            rseconds     => 60,
            rhitcount    => 5,
            rttl         => true,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp85, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(
            %r{-A INPUT -d 30.0.0.0\/(8|255\.0\.0\.0) -m recent --rcheck --seconds 60 --hitcount 5 --rttl --name list1 (--mask 255.255.255.255 )?--rsource -m comment --comment "598 - test"},
          )
        end
      end
    end

    context 'when update' do
      pp86 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '599 - test':
            ensure       => 'present',
            chain        => 'INPUT',
            destination  => '30.0.0.0/8',
            proto        => 'all',
            table        => 'filter',
            recent       => 'update',
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp86, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -d 30.0.0.0\/(8|255\.0\.0\.0) -m recent --update --name DEFAULT (--mask 255.255.255.255 )?--rsource -m comment --comment "599 - test"})
        end
      end
    end

    context 'when remove' do
      pp87 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '600 - test':
            ensure       => 'present',
            chain        => 'INPUT',
            destination  => '30.0.0.0/8',
            proto        => 'all',
            table        => 'filter',
            recent       => 'remove',
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp87, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -d 30.0.0.0\/(8|255\.0\.0\.0) -m recent --remove --name DEFAULT (--mask 255.255.255.255 )?--rsource -m comment --comment "600 - test"})
        end
      end
    end
  end

  describe 'mac_source' do
    context 'when 0A:1B:3C:4D:5E:6F' do
      pp88 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '610 - test':
            ensure      => present,
            source      => '10.1.5.28/32',
            mac_source  => '0A:1B:3C:4D:5E:6F',
            chain       => 'INPUT',
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp88, catch_failures: true)
      end
      it 'contains the rule' do
        shell('iptables-save') do |r|
          if os[:family] == 'redhat' && os[:release].start_with?('5')
            expect(r.stdout).to match(%r{-A INPUT -s 10.1.5.28 -p tcp -m mac --mac-source 0A:1B:3C:4D:5E:6F -m comment --comment "610 - test"})
          else
            expect(r.stdout).to match(%r{-A INPUT -s 10.1.5.28\/(32|255\.255\.255\.255) -p tcp -m mac --mac-source 0A:1B:3C:4D:5E:6F -m comment --comment "610 - test"})
          end
        end
      end
      # rubocop:enable RSpec/ExampleLength : Cannot reduce lines to required size
    end
  end

  describe 'reset' do
    it 'deletes all rules' do
      shell('ip6tables --flush')
      shell('iptables --flush; iptables -t nat --flush; iptables -t mangle --flush')
    end
  end

  describe 'tee_gateway', unless: (os[:family] == 'redhat' && os[:release].start_with?('5', '6')) || (os[:family] == 'sles') do
    context 'when 10.0.0.2' do
      pp1 = <<-PUPPETCODE
          class { '::firewall': }
          firewall {
            '810 - tee_gateway':
              chain   => 'PREROUTING',
              table   => 'mangle',
              jump    => 'TEE',
              gateway => '10.0.0.2',
              proto   => all,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp1, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save -t mangle') do |r|
          expect(r.stdout).to match(%r{-A PREROUTING -m comment --comment "810 - tee_gateway" -j TEE --gateway 10.0.0.2})
        end
      end
    end
  end

  describe 'time tests', unless: (os[:family] == 'redhat' && os[:release].start_with?('5', '6')) || (os[:family] == 'sles') do
    context 'when set all time parameters' do
      pp1 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '805 - test':
            proto              => tcp,
            dport              => '8080',
            action             => accept,
            chain              => 'OUTPUT',
            date_start         => '2016-01-19T04:17:07',
            date_stop          => '2038-01-19T04:17:07',
            time_start         => '6:00',
            time_stop          => '17:00:00',
            month_days         => '7',
            week_days          => 'Tue',
            kernel_timezone    => true,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp1, catch_failures: true)
        apply_manifest(pp1, catch_changes: do_catch_changes)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(
            %r{-A OUTPUT -p tcp -m multiport --dports 8080 -m time --timestart 06:00:00 --timestop 17:00:00 --monthdays 7 --weekdays Tue --datestart 2016-01-19T04:17:07 --datestop 2038-01-19T04:17:07 --kerneltz -m comment --comment "805 - test" -j ACCEPT}, # rubocop:disable Metrics/LineLength
          )
        end
      end
    end
  end

  describe 'to' do
    context 'when Destination netmap 192.168.1.1' do
      pp89 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '569 - test':
            proto  => tcp,
            table  => 'nat',
            chain  => 'PREROUTING',
            jump   => 'NETMAP',
            source => '200.200.200.200',
            to => '192.168.1.1',
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp89, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save -t nat') do |r|
          expect(r.stdout).to match(%r{-A PREROUTING -s 200.200.200.200(\/32)? -p tcp -m comment --comment "569 - test" -j NETMAP --to 192.168.1.1})
        end
      end
    end

    describe 'reset' do
      it 'deletes all rules' do
        shell('ip6tables --flush')
        shell('iptables --flush; iptables -t nat --flush; iptables -t mangle --flush')
      end
    end

    context 'when Source netmap 192.168.1.1' do
      pp90 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '569 - test':
            proto  => tcp,
            table  => 'nat',
            chain  => 'POSTROUTING',
            jump   => 'NETMAP',
            destination => '200.200.200.200',
            to => '192.168.1.1',
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp90, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save -t nat') do |r|
          expect(r.stdout).to match(%r{-A POSTROUTING -d 200.200.200.200(\/32)? -p tcp -m comment --comment "569 - test" -j NETMAP --to 192.168.1.1})
        end
      end
    end
  end
end
