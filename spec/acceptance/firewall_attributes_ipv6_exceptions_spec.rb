require 'spec_helper_acceptance'

describe 'firewall attribute testing, exceptions' do
  before(:all) do
    iptables_flush_all_tables
    ip6tables_flush_all_tables
  end

  describe 'attributes test', unless: (os[:family] == 'redhat' && os[:release].start_with?('5', '6')) || (os[:family] == 'sles') do
    describe 'hop_limit' do
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

    describe 'src_range' do
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

    ['dst_type', 'src_type'].each do |type|
      describe type.to_s do
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

        context 'when duplicated LOCAL' do
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

        context 'when multiple addrtype fail', if: (os[:family] == 'redhat' && os[:release].start_with?('5')) do
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

    # ipset is hard to test, only testing on ubuntu 14
    describe 'ipset', if: (host_inventory['facter']['os']['name'] == 'Ubuntu' && os[:release].start_with?('14')) do
      before(:all) do
        pp = <<-PUPPETCODE
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
        apply_manifest(pp, catch_failures: true)        
      end

      it 'contains the rule' do
        shell('ip6tables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -p tcp -m set --match-set blacklist src,dst -m set ! --match-set honeypot dst -m comment --comment "612 - test" -j DROP})
        end
      end
    end
  end

  describe 'attributes test (unless redhat 5)', unless: (os[:family] == 'redhat' && os[:release].start_with?('5')) do
    before(:all) do
      pp = <<-PUPPETCODE
        firewall { '701 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          port   => '701',
          action => accept,
          physdev_in => 'eth0',
        }
        firewall { '702 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          port   => '702',
          action => accept,
          physdev_out => 'eth1',
        }
        firewall { '703 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          port   => '703',
          action => accept,
          physdev_in => 'eth0',
          physdev_out => 'eth1',
        }
        firewall { '704 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          port   => '704',
          action => accept,
          physdev_is_bridged => true,
        }
        firewall { '705 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          port   => '705',
          action => accept,
          physdev_in => 'eth0',
          physdev_is_bridged => true,
        }
        firewall { '706 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          port   => '706',
          action => accept,
          physdev_out => 'eth1',
          physdev_is_bridged => true,
        }
        firewall { '707 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          port   => '707',
          action => accept,
          physdev_in => 'eth0',
          physdev_out => 'eth1',
          physdev_is_bridged => true,
        }
        firewall { '708 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          port   => '708',
          action => accept,
          physdev_is_in => true,
        }
        firewall { '709 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          port   => '709',
          action => accept,
          physdev_is_out => true,
        }
        firewall { '1002 - set_dscp':
            proto     => 'tcp',
            jump      => 'DSCP',
            set_dscp  => '0x01',
            port      => '997',
            chain     => 'OUTPUT',
            table     => 'mangle',
            provider  => 'ip6tables',
        }
        firewall { '1003 EF - set_dscp_class':
            proto          => 'tcp',
            jump           => 'DSCP',
            port           => '997',
            set_dscp_class => 'EF',
            chain          => 'OUTPUT',
            table          => 'mangle',
            provider       => 'ip6tables',
        }
        firewall { '502 - set_mss':
            proto     => 'tcp',
            tcp_flags => 'SYN,RST SYN',
            jump      => 'TCPMSS',
            set_mss   => '1360',
            mss       => '1361:1541',
            chain     => 'FORWARD',
            table     => 'mangle',
            provider  => 'ip6tables',
        }
        firewall { '503 - clamp_mss_to_pmtu':
            proto             => 'tcp',
            chain             => 'FORWARD',
            tcp_flags         => 'SYN,RST SYN',
            jump              => 'TCPMSS',
            clamp_mss_to_pmtu => true,
            provider          => 'ip6tables',
        }
        firewall { '803 - hashlimit_upto test ip6':
          chain                   => 'INPUT',
          provider                => 'ip6tables',
          hashlimit_name          => 'upto-ip6',
          hashlimit_upto          => '16/sec',
          hashlimit_burst         => '640',
          hashlimit_htable_size   => '1310000',
          hashlimit_htable_max    => '320000',
          hashlimit_htable_expire => '36000000',
          action                  => accept,
        }

      PUPPETCODE
      apply_manifest(pp, catch_failures: true)
      apply_manifest(pp, catch_changes: do_catch_changes)
    end

    let(:result) { shell('ip6tables-save') }

    it 'physdev_in is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-in eth0 -m multiport --ports 701 -m comment --comment "701 - test" -j ACCEPT})
    end
    it 'physdev_out is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-out eth1 -m multiport --ports 702 -m comment --comment "702 - test" -j ACCEPT})
    end
    it 'physdev_in and physdev_out is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-in eth0 --physdev-out eth1 -m multiport --ports 703 -m comment --comment "703 - test" -j ACCEPT})
    end
    it 'physdev_is_bridged is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-is-bridged -m multiport --ports 704 -m comment --comment "704 - test" -j ACCEPT})
    end
    it 'physdev_in and physdev_is_bridged is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-in eth0 --physdev-is-bridged -m multiport --ports 705 -m comment --comment "705 - test" -j ACCEPT})
    end
    it 'physdev_out and physdev_is_bridged is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-out eth1 --physdev-is-bridged -m multiport --ports 706 -m comment --comment "706 - test" -j ACCEPT})
    end
    it 'physdev_in and physdev_out and physdev_is_bridged is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-in eth0 --physdev-out eth1 --physdev-is-bridged -m multiport --ports 707 -m comment --comment "707 - test" -j ACCEPT})
    end
    it 'physdev_is_in is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-is-in -m multiport --ports 708 -m comment --comment "708 - test" -j ACCEPT})
    end
    it 'physdev_is_out is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-is-out -m multiport --ports 709 -m comment --comment "709 - test" -j ACCEPT})
    end
    it 'set_dscp is set' do
      expect(result.stdout).to match(%r{-A OUTPUT -p tcp -m multiport --ports 997 -m comment --comment "1002 - set_dscp" -j DSCP --set-dscp 0x01})
    end
    it 'set_dscp_class is set' do
      expect(result.stdout).to match(%r{-A OUTPUT -p tcp -m multiport --ports 997 -m comment --comment "1003 EF - set_dscp_class" -j DSCP --set-dscp 0x2e})
    end
    it 'set_mss and mss is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1541 -m comment --comment "502 - set_mss" -j TCPMSS --set-mss 1360})
    end
    it 'clamp_mss_to_pmtu is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "503 - clamp_mss_to_pmtu" -j TCPMSS --clamp-mss-to-pmtu})
    end
    it 'hashlimit_name set to "upto-ip6"' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m hashlimit --hashlimit-upto 16\/sec --hashlimit-burst 640 --hashlimit-name upto-ip6 --hashlimit-htable-size 1310000 --hashlimit-htable-max 320000 --hashlimit-htable-expire 36000000 -m comment --comment "803 - hashlimit_upto test ip6" -j ACCEPT}) # rubocop:disable Metrics/LineLength : Cannot reduce line to required length
    end
  end
end
