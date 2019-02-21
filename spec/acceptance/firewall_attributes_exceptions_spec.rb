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
      context 'when LOCAL --limit-iface-in', unless: (fact('osfamily') == 'RedHat' && fact('operatingsystemmajrelease') <= '5') do
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

      context 'when LOCAL --limit-iface-in fail', if: (fact('osfamily') == 'RedHat' && fact('operatingsystemmajrelease') <= '5') do
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

      context 'when duplicated LOCAL', unless: (fact('osfamily') == 'RedHat' && fact('operatingsystemmajrelease') <= '5') do
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

      context 'when multiple addrtype', unless: (fact('osfamily') == 'RedHat' && fact('operatingsystemmajrelease') <= '5') do
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

      context 'when multiple addrtype fail', if: (fact('osfamily') == 'RedHat' && fact('operatingsystemmajrelease') <= '5') do
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

  if default['platform'] !~ %r{el-5} && default['platform'] !~ %r{sles}
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

    describe 'checksum_fill6' do
      context 'when virbr' do
        pp39 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '576 - test':
              proto  => udp,
              table  => 'mangle',
              outiface => 'virbr0',
              chain  => 'POSTROUTING',
              dport => '68',
              jump  => 'CHECKSUM',
              checksum_fill => true,
              provider => ip6tables,
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp39, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save -t mangle') do |r|
            expect(r.stdout).to match(%r{-A POSTROUTING -o virbr0 -p udp -m multiport --dports 68 -m comment --comment "576 - test" -j CHECKSUM --checksum-fill})
          end
        end
      end
    end
  end

  # RHEL5 does not support --random
  if default['platform'] !~ %r{el-5} && default['platform'] !~ %r{sles-10}
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

  # iptables version 1.3.5 is not suppored by the ip6tables provider
  # iptables version 1.4.7 fails for multiple hl entries
  if default['platform'] !~ %r{(el-5|el-6|sles-10|sles-11)}
    describe 'hop_limit' do
      context 'when 5' do
        pp42 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '571 - test':
              ensure => present,
              proto => tcp,
              port   => '571',
              action => accept,
              hop_limit => '5',
              provider => 'ip6tables',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp42, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p tcp -m multiport --ports 571 -m hl --hl-eq 5 -m comment --comment "571 - test" -j ACCEPT})
          end
        end
      end

      context 'when invalid' do
        pp43 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '571 - test':
              ensure => present,
              proto => tcp,
              port   => '571',
              action => accept,
              hop_limit => 'invalid',
              provider => 'ip6tables',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp43, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{Invalid value "invalid".})
          end
        end

        it 'does not contain the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m multiport --ports 571 -m comment --comment "571 - test" -m hl --hl-eq invalid -j ACCEPT})
          end
        end
      end
    end

    describe 'ishasmorefrags' do
      context 'when true' do
        pp44 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '587 - test':
              ensure => present,
              proto => tcp,
              port   => '587',
              action => accept,
              ishasmorefrags => true,
              provider => 'ip6tables',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp44, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{A INPUT -p tcp -m frag --fragid 0 --fragmore -m multiport --ports 587 -m comment --comment "587 - test" -j ACCEPT})
          end
        end
      end

      context 'when false' do
        pp45 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '588 - test':
              ensure => present,
              proto => tcp,
              port   => '588',
              action => accept,
              ishasmorefrags => false,
              provider => 'ip6tables',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp45, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p tcp -m multiport --ports 588 -m comment --comment "588 - test" -j ACCEPT})
          end
        end
      end
    end

    describe 'islastfrag' do
      context 'when true' do
        pp46 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '589 - test':
              ensure => present,
              proto => tcp,
              port   => '589',
              action => accept,
              islastfrag => true,
              provider => 'ip6tables',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp46, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p tcp -m frag --fragid 0 --fraglast -m multiport --ports 589 -m comment --comment "589 - test" -j ACCEPT})
          end
        end
      end

      context 'when false' do
        pp47 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '590 - test':
              ensure => present,
              proto => tcp,
              port   => '590',
              action => accept,
              islastfrag => false,
              provider => 'ip6tables',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp47, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p tcp -m multiport --ports 590 -m comment --comment "590 - test" -j ACCEPT})
          end
        end
      end
    end

    describe 'isfirstfrag' do
      context 'when true' do
        pp48 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '591 - test':
              ensure => present,
              proto => tcp,
              port   => '591',
              action => accept,
              isfirstfrag => true,
              provider => 'ip6tables',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp48, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p tcp -m frag --fragid 0 --fragfirst -m multiport --ports 591 -m comment --comment "591 - test" -j ACCEPT})
          end
        end
      end

      context 'when false' do
        pp49 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '592 - test':
              ensure => present,
              proto => tcp,
              port   => '592',
              action => accept,
              isfirstfrag => false,
              provider => 'ip6tables',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp49, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p tcp -m multiport --ports 592 -m comment --comment "592 - test" -j ACCEPT})
          end
        end
      end
    end

    describe 'tcp_flags' do
      context 'when FIN,SYN ACK' do
        pp50 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '593 - test':
            proto  => tcp,
            action => accept,
            tcp_flags => 'FIN,SYN ACK',
            provider => 'ip6tables',
          }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp50, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN ACK -m comment --comment "593 - test" -j ACCEPT})
          end
        end
      end
    end

    describe 'src_range' do
      context 'when 2001:db8::1-2001:db8::ff' do
        pp51 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '601 - test':
            proto     => tcp,
            port      => '601',
            action    => accept,
            src_range => '2001:db8::1-2001:db8::ff',
            provider  => 'ip6tables',
          }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp51, catch_failures: true)
          apply_manifest(pp51, catch_changes: do_catch_changes)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p tcp -m iprange --src-range 2001:db8::1-2001:db8::ff -m multiport --ports 601 -m comment --comment "601 - test" -j ACCEPT})
          end
        end
      end

      # Invalid IP
      context 'when 2001::db8::1-2001:db8::ff' do
        pp52 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '601 - test':
            proto     => tcp,
            port      => '601',
            action    => accept,
            provider  => 'ip6tables',
            src_range => '2001::db8::1-2001:db8::ff',
          }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp52, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{Invalid IP address "2001::db8::1" in range "2001::db8::1-2001:db8::ff"})
          end
        end

        it 'does not contain the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m iprange --src-range 2001::db8::1-2001:db8::ff -m multiport --ports 601 -m comment --comment "601 - test" -j ACCEPT})
          end
        end
      end
    end

    describe 'dst_range' do
      context 'when 2001:db8::1-2001:db8::ff' do
        pp53 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '602 - test':
            proto     => tcp,
            port      => '602',
            action    => accept,
            dst_range => '2001:db8::1-2001:db8::ff',
            provider  => 'ip6tables',
          }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp53, catch_failures: true)
          apply_manifest(pp53, catch_changes: do_catch_changes)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p tcp -m iprange --dst-range 2001:db8::1-2001:db8::ff -m multiport --ports 602 -m comment --comment "602 - test" -j ACCEPT})
          end
        end
      end

      # Invalid IP
      context 'when 2001::db8::1-2001:db8::ff' do
        pp54 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '602 - test':
            proto     => tcp,
            port      => '602',
            action    => accept,
            provider  => 'ip6tables',
            dst_range => '2001::db8::1-2001:db8::ff',
          }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp54, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{Invalid IP address "2001::db8::1" in range "2001::db8::1-2001:db8::ff"})
          end
        end

        it 'does not contain the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m iprange --dst-range 2001::db8::1-2001:db8::ff -m multiport --ports 602 -m comment --comment "602 - test" -j ACCEPT})
          end
        end
      end
    end

    describe 'mac_source' do
      context 'when 0A:1B:3C:4D:5E:6F' do
        pp55 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '604 - test':
            ensure      => present,
            source      => '2001:db8::1/128',
            mac_source  => '0A:1B:3C:4D:5E:6F',
            chain       => 'INPUT',
            provider    => 'ip6tables',
          }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp55, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -s 2001:db8::1\/(128|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) -p tcp -m mac --mac-source 0A:1B:3C:4D:5E:6F -m comment --comment "604 - test"})
          end
        end
      end
    end

    # ip6tables has limited `-m socket` support
    if default['platform'] !~ %r{el-5} && default['platform'] !~ %r{sles}
      describe 'socket' do
        context 'when true' do
          pp56 = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '605 - test':
                ensure   => present,
                proto    => tcp,
                port     => '605',
                action   => accept,
                chain    => 'INPUT',
                socket   => true,
                provider => 'ip6tables',
              }
          PUPPETCODE
          it 'applies' do
            apply_manifest(pp56, catch_failures: true)
          end

          it 'contains the rule' do
            shell('ip6tables-save') do |r|
              expect(r.stdout).to match(%r{-A INPUT -p tcp -m multiport --ports 605 -m socket -m comment --comment "605 - test" -j ACCEPT})
            end
          end
        end

        context 'when false' do
          pp57 = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '606 - test':
                ensure   => present,
                proto    => tcp,
                port     => '606',
                action   => accept,
                chain    => 'INPUT',
                socket   => false,
                provider => 'ip6tables',
              }
          PUPPETCODE
          it 'applies' do
            apply_manifest(pp57, catch_failures: true)
          end

          it 'contains the rule' do
            shell('ip6tables-save') do |r|
              expect(r.stdout).to match(%r{-A INPUT -p tcp -m multiport --ports 606 -m comment --comment "606 - test" -j ACCEPT})
            end
          end
        end
      end
    end

    describe 'ipsec_policy' do
      context 'when ipsec' do
        pp58 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '607 - test':
              ensure       => 'present',
              action       => 'reject',
              chain        => 'OUTPUT',
              destination  => '2001:db8::1/128',
              ipsec_dir    => 'out',
              ipsec_policy => 'ipsec',
              proto        => 'all',
              reject       => 'icmp6-adm-prohibited',
              table        => 'filter',
              provider     => 'ip6tables',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp58, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{-A OUTPUT -d 2001:db8::1\/(128|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) -m policy --dir out --pol ipsec -m comment --comment "607 - test" -j REJECT --reject-with icmp6-adm-prohibited}) # rubocop:disable Metrics/LineLength : Cannot reduce line to required length
          end
        end
      end

      context 'when none' do
        pp59 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '608 - test':
            ensure       => 'present',
            action       => 'reject',
            chain        => 'OUTPUT',
            destination  => '2001:db8::1/128',
            ipsec_dir    => 'out',
            ipsec_policy => 'none',
            proto        => 'all',
            reject       => 'icmp6-adm-prohibited',
            table        => 'filter',
            provider     => 'ip6tables',
          }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp59, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{-A OUTPUT -d 2001:db8::1\/(128|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) -m policy --dir out --pol none -m comment --comment "608 - test" -j REJECT --reject-with icmp6-adm-prohibited}) # rubocop:disable Metrics/LineLength : Cannot reduce line to required length
          end
        end
      end
    end

    describe 'ipsec_dir' do
      context 'when out' do
        pp60 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '609 - test':
            ensure       => 'present',
            action       => 'reject',
            chain        => 'OUTPUT',
            destination  => '2001:db8::1/128',
            ipsec_dir    => 'out',
            ipsec_policy => 'ipsec',
            proto        => 'all',
            reject       => 'icmp6-adm-prohibited',
            table        => 'filter',
            provider     => 'ip6tables',
          }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp60, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{-A OUTPUT -d 2001:db8::1\/(128|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) -m policy --dir out --pol ipsec -m comment --comment "609 - test" -j REJECT --reject-with icmp6-adm-prohibited}) # rubocop:disable Metrics/LineLength : Cannot reduce line to required length
          end
        end
      end

      context 'when in' do
        pp61 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '610 - test':
            ensure       => 'present',
            action       => 'reject',
            chain        => 'INPUT',
            destination  => '2001:db8::1/128',
            ipsec_dir    => 'in',
            ipsec_policy => 'none',
            proto        => 'all',
            reject       => 'icmp6-adm-prohibited',
            table        => 'filter',
            provider     => 'ip6tables',
          }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp61, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -d 2001:db8::1\/(128|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) -m policy --dir in --pol none -m comment --comment "610 - test" -j REJECT --reject-with icmp6-adm-prohibited}) # rubocop:disable Metrics/LineLength : Cannot reduce line to required length
          end
        end
      end
    end

    describe 'set_mark' do
      context 'when 0x3e8/0xffffffff' do
        pp62 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '611 - test':
              ensure => present,
              chain => 'OUTPUT',
              proto => tcp,
              port   => '611',
              jump => 'MARK',
              table => 'mangle',
              set_mark => '0x3e8/0xffffffff',
              provider => 'ip6tables',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp62, catch_failures: true)
        end

        it 'contains the rule' do
          shell('ip6tables-save -t mangle') do |r|
            expect(r.stdout).to match(%r{-A OUTPUT -p tcp -m multiport --ports 611 -m comment --comment "611 - test" -j MARK --set-xmark 0x3e8\/0xffffffff})
          end
        end
      end
    end

    # ip6tables only supports ipset, addrtype, and mask on a limited set of platforms
    if default['platform'] =~ %r{el-7} || default['platform'] =~ %r{ubuntu-14\.04}
      # ipset is really difficult to test, just testing on one platform
      if default['platform'] =~ %r{ubuntu-14\.04}
        describe 'ipset' do
          pp63 = <<-PUPPETCODE
            exec { 'hackery pt 1':
              command => 'service iptables-persistent flush',
              path    => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            }
            package { 'ipset':
              ensure  => present,
              require => Exec['hackery pt 1'],
            }
            exec { 'hackery pt 2':
              command => 'service iptables-persistent start',
              path    => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
              require => Package['ipset'],
            }
            class { '::firewall': }
            exec { 'create ipset blacklist':
              command => 'ipset create blacklist hash:ip,port family inet6 maxelem 1024 hashsize 65535 timeout 120',
              path    => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
              require => Package['ipset'],
            }
            -> exec { 'create ipset honeypot':
              command => 'ipset create honeypot hash:ip family inet6 maxelem 1024 hashsize 65535 timeout 120',
              path    => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            }
            -> exec { 'add blacklist':
              command => 'ipset add blacklist 2001:db8::1,80',
              path    => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            }
            -> exec { 'add honeypot':
              command => 'ipset add honeypot 2001:db8::5',
              path    => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            }
            firewall { '612 - test':
              ensure   => present,
              chain    => 'INPUT',
              proto    => tcp,
              action   => drop,
              ipset    => ['blacklist src,dst', '! honeypot dst'],
              provider => 'ip6tables',
              require  => Exec['add honeypot'],
            }
          PUPPETCODE
          it 'applies' do
            apply_manifest(pp63, catch_failures: true)
          end

          it 'contains the rule' do
            shell('ip6tables-save') do |r|
              expect(r.stdout).to match(%r{-A INPUT -p tcp -m set --match-set blacklist src,dst -m set ! --match-set honeypot dst -m comment --comment "612 - test" -j DROP})
            end
          end
        end
      end

      ['dst_type', 'src_type'].each do |type|
        describe type.to_s do
          context 'when MULTICAST' do
            pp65 = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '603 - test':
                proto    => tcp,
                action   => accept,
                #{type}  => 'MULTICAST',
                provider => 'ip6tables',
              }
            PUPPETCODE
            it 'applies' do
              apply_manifest(pp65, catch_failures: true)
              apply_manifest(pp65, catch_changes: do_catch_changes)
            end

            it 'contains the rule' do
              shell('ip6tables-save') do |r|
                expect(r.stdout).to match(%r{-A INPUT -p tcp -m addrtype\s.*\sMULTICAST -m comment --comment "603 - test" -j ACCEPT})
              end
            end
          end

          context 'when ! MULTICAST' do
            pp66 = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '603 - test inversion':
                proto    => tcp,
                action   => accept,
                #{type}  => '! MULTICAST',
                provider => 'ip6tables',
              }
            PUPPETCODE
            it 'applies' do
              apply_manifest(pp66, catch_failures: true)
              apply_manifest(pp66, catch_changes: do_catch_changes)
            end

            it 'contains the rule' do
              shell('ip6tables-save') do |r|
                expect(r.stdout).to match(%r{-A INPUT -p tcp -m addrtype( !\s.*\sMULTICAST|\s.*\s! MULTICAST) -m comment --comment "603 - test inversion" -j ACCEPT})
              end
            end
          end

          context 'when BROKEN' do
            pp67 = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '603 - test':
                proto    => tcp,
                action   => accept,
                #{type}  => 'BROKEN',
                provider => 'ip6tables',
              }
            PUPPETCODE
            it 'fails' do
              apply_manifest(pp67, expect_failures: true) do |r|
                expect(r.stderr).to match(%r{Invalid value "BROKEN".})
              end
            end

            it 'does not contain the rule' do
              shell('ip6tables-save') do |r|
                expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m addrtype\s.*\sBROKEN -m comment --comment "603 - test" -j ACCEPT})
              end
            end
          end

          context 'when LOCAL --limit-iface-in', unless: (fact('osfamily') == 'RedHat' && fact('operatingsystemmajrelease') <= '5') do
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

          context 'when LOCAL --limit-iface-in fail', if: (fact('osfamily') == 'RedHat' && fact('operatingsystemmajrelease') <= '5') do
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

          context 'when duplicated LOCAL', unless: (fact('osfamily') == 'RedHat' && fact('operatingsystemmajrelease') <= '5') do
            pp104 = <<-PUPPETCODE
                class { '::firewall': }
                firewall { '619 - test':
                  proto    => tcp,
                  action   => accept,
                  #{type}  => ['LOCAL', 'LOCAL'],
                  provider => 'ip6tables',
                }
            PUPPETCODE
            it 'fails' do
              apply_manifest(pp104, expect_failures: true) do |r|
                expect(r.stderr).to match(%r{#{type} elements must be unique})
              end
            end

            it 'does not contain the rule' do
              shell('ip6tables-save') do |r|
                expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m addrtype\s.*\sLOCAL -m addrtype\s.*\sLOCAL -m comment --comment "619 - test" -j ACCEPT})
              end
            end
          end

          context 'when multiple addrtype', unless: (fact('osfamily') == 'RedHat' && fact('operatingsystemmajrelease') <= '5') do
            pp105 = <<-PUPPETCODE
                class { '::firewall': }
                firewall { '620 - test':
                  proto    => tcp,
                  action   => accept,
                  #{type}  => ['LOCAL', '! LOCAL'],
                  provider => 'ip6tables',
                }
            PUPPETCODE
            it 'applies' do
              apply_manifest(pp105, catch_failures: true)
            end

            it 'contains the rule' do
              shell('ip6tables-save') do |r|
                expect(r.stdout).to match(%r{-A INPUT -p tcp -m addrtype --#{type.tr('_', '-')} LOCAL -m addrtype ! --#{type.tr('_', '-')} LOCAL -m comment --comment "620 - test" -j ACCEPT})
              end
            end
          end

          context 'when multiple addrtype fail', if: (fact('osfamily') == 'RedHat' && fact('operatingsystemmajrelease') <= '5') do
            pp106 = <<-PUPPETCODE
                class { '::firewall': }
                firewall { '616 - test':
                  proto    => tcp,
                  action   => accept,
                  #{type}  => ['LOCAL', '! LOCAL'],
                  provider => 'ip6tables',
                }
            PUPPETCODE
            it 'fails' do
              apply_manifest(pp106, expect_failures: true) do |r|
                expect(r.stderr).to match(%r{Multiple #{type} elements are available from iptables version})
              end
            end

            it 'does not contain the rule' do
              shell('ip6tables-save') do |r|
                expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m addrtype --#{type.tr('_', '-')} LOCAL -m addrtype ! --#{type.tr('_', '-')} LOCAL -m comment --comment "616 - test" -j ACCEPT})
              end
            end
          end
        end
      end
    end

  end

  # iptables version 1.3.5 does not support masks on MARK rules
  if default['platform'] !~ %r{el-5} && default['platform'] !~ %r{sles-10}
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
  describe 'socket', unless: (default['platform'] =~ %r{el-5} || fact('operatingsystem') == 'SLES') do
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
          expect(r.stdout).to match(%r{-A INPUT -d 30.0.0.0\/(8|255\.0\.0\.0) -m recent --rcheck --seconds 60 --hitcount 5 --rttl --name list1 (--mask 255.255.255.255 )?--rsource -m comment --comment "598 - test"}) # rubocop:disable Metrics/LineLength : Cannot reduce line to required length
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
          if (fact('osfamily') == 'RedHat' && fact('operatingsystemmajrelease') == '5') || (default['platform'] =~ %r{sles-10})
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
