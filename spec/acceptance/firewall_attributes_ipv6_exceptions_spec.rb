require 'spec_helper_acceptance'

describe 'firewall ipv6 attribute testing, exceptions' do
  before(:all) do
    iptables_flush_all_tables
    ip6tables_flush_all_tables
    if os[:family] == 'debian' && os[:release] == '10'
      # in order to avoid this stderr: Warning: ip6tables-legacy tables present, use ip6tables-legacy-save to see them\n"
      run_shell('update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy')
    end
  end

  describe 'standard attributes', unless: (os[:family] == 'redhat' && os[:release].start_with?('5', '6')) || (os[:family] == 'sles') do
    describe 'dst_range' do
      context 'when 2001::db8::1-2001:db8::ff' do
        pp = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '602 - test':
            proto     => tcp,
            dport      => '602',
            action    => accept,
            provider  => 'ip6tables',
            dst_range => '2001::db8::1-2001:db8::ff',
          }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{Invalid IP address "2001::db8::1" in range "2001::db8::1-2001:db8::ff"})
          end
        end

        it 'does not contain the rule' do
          run_shell('ip6tables-save') do |r|
            expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m iprange --dst-range 2001::db8::1-2001:db8::ff -m multiport --ports 602 -m comment --comment "602 - test" -j ACCEPT})
          end
        end
      end
    end

    ['dst_type', 'src_type'].each do |type|
      describe type.to_s do
        context 'when BROKEN' do
          pp = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '603 - test':
                proto    => tcp,
                action   => accept,
                #{type}  => 'BROKEN',
                provider => 'ip6tables',
              }
            PUPPETCODE
          it 'fails' do
            apply_manifest(pp, expect_failures: true) do |r|
              expect(r.stderr).to match(%r{Invalid value "BROKEN".})
            end
          end

          it 'does not contain the rule' do
            run_shell('ip6tables-save') do |r|
              expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m addrtype\s.*\sBROKEN -m comment --comment "603 - test" -j ACCEPT})
            end
          end
        end

        context 'when duplicated LOCAL' do
          pp = <<-PUPPETCODE
                class { '::firewall': }
                firewall { '619 - test':
                  proto    => tcp,
                  action   => accept,
                  #{type}  => ['LOCAL', 'LOCAL'],
                  provider => 'ip6tables',
                }
            PUPPETCODE
          it 'fails' do
            apply_manifest(pp, expect_failures: true) do |r|
              expect(r.stderr).to match(%r{#{type} elements must be unique})
            end
          end

          it 'does not contain the rule' do
            run_shell('ip6tables-save') do |r|
              expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m addrtype\s.*\sLOCAL -m addrtype\s.*\sLOCAL -m comment --comment "619 - test" -j ACCEPT})
            end
          end
        end

        context 'when multiple addrtype fail', if: (os[:family] == 'redhat' && os[:release].start_with?('5')) do
          pp = <<-PUPPETCODE
                class { '::firewall': }
                firewall { '616 - test':
                  proto    => tcp,
                  action   => accept,
                  #{type}  => ['LOCAL', '! LOCAL'],
                  provider => 'ip6tables',
                }
            PUPPETCODE
          it 'fails' do
            apply_manifest(pp, expect_failures: true) do |r|
              expect(r.stderr).to match(%r{Multiple #{type} elements are available from iptables version})
            end
          end

          it 'does not contain the rule' do
            run_shell('ip6tables-save') do |r|
              expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m addrtype --#{type.tr('_', '-')} LOCAL -m addrtype ! --#{type.tr('_', '-')} LOCAL -m comment --comment "616 - test" -j ACCEPT})
            end
          end
        end
      end
    end

    describe 'hop_limit' do
      context 'when invalid' do
        pp = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '571 - test':
              ensure => present,
              proto => tcp,
              dport   => '571',
              action => accept,
              hop_limit => 'invalid',
              provider => 'ip6tables',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{Invalid value "invalid".})
          end
        end

        it 'does not contain the rule' do
          run_shell('ip6tables-save') do |r|
            expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m multiport --dports 571 -m comment --comment "571 - test" -m hl --hl-eq invalid -j ACCEPT})
          end
        end
      end
    end

    # ipset is hard to test, only testing on ubuntu 14
    describe 'ipset', if: (os[:family] == 'redhat' && os[:release].start_with?('14')) do
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
        run_shell('ip6tables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -p tcp -m set --match-set blacklist src,dst -m set ! --match-set honeypot dst -m comment --comment "612 - test" -j DROP})
        end
      end
    end

    describe 'src_range' do
      context 'when 2001::db8::1-2001:db8::ff' do
        pp = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '601 - test':
            proto     => tcp,
            dport      => '601',
            action    => accept,
            provider  => 'ip6tables',
            src_range => '2001::db8::1-2001:db8::ff',
          }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{Invalid IP address "2001::db8::1" in range "2001::db8::1-2001:db8::ff"})
          end
        end

        it 'does not contain the rule' do
          run_shell('ip6tables-save') do |r|
            expect(r.stdout).not_to match(%r{-A INPUT -p tcp -m iprange --src-range 2001::db8::1-2001:db8::ff -m multiport --dports 601 -m comment --comment "601 - test" -j ACCEPT})
          end
        end
      end
    end

    unless os[:family] == 'redhat' && os[:release].start_with?('8')
      describe 'time tests' do
        context 'when set all time parameters' do
          pp1 = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '805 - time':
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
                provider           => 'ip6tables',
              }
          PUPPETCODE
          it 'applies' do
            idempotent_apply(pp1)
          end

          it 'contains the rule' do
            run_shell('ip6tables-save') do |r|
              expect(r.stdout).to match(
                %r{-A OUTPUT -p tcp -m multiport --dports 8080 -m time --timestart 06:00:00 --timestop 17:00:00 --monthdays 7 --weekdays Tue --datestart 2016-01-19T04:17:07 --datestop 2038-01-19T04:17:07 --kerneltz -m comment --comment "805 - time" -j ACCEPT}, # rubocop:disable Layout/LineLength
              )
            end
          end
        end
      end
    end
  end

  describe 'unless redhat 5 happy path', unless: (os[:family] == 'redhat' && os[:release].start_with?('5')) do
    before(:all) do
      pp = <<-PUPPETCODE
        firewall { '701 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          dport   => '701',
          action => accept,
          physdev_in => 'eth0',
        }
        firewall { '702 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          dport   => '702',
          action => accept,
          physdev_out => 'eth1',
        }
        firewall { '703 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          dport   => '703',
          action => accept,
          physdev_in => 'eth0',
          physdev_out => 'eth1',
        }
        firewall { '704 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          dport   => '704',
          action => accept,
          physdev_is_bridged => true,
        }
        firewall { '705 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          dport   => '705',
          action => accept,
          physdev_in => 'eth0',
          physdev_is_bridged => true,
        }
        firewall { '706 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          dport   => '706',
          action => accept,
          physdev_out => 'eth1',
          physdev_is_bridged => true,
        }
        firewall { '707 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          dport   => '707',
          action => accept,
          physdev_in => 'eth0',
          physdev_out => 'eth1',
          physdev_is_bridged => true,
        }
        firewall { '708 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          dport   => '708',
          action => accept,
          physdev_is_in => true,
        }
        firewall { '709 - test':
          provider => 'ip6tables',
          chain => 'FORWARD',
          proto  => tcp,
          dport   => '709',
          action => accept,
          physdev_is_out => true,
        }
        firewall { '1002 - set_dscp':
            proto     => 'tcp',
            jump      => 'DSCP',
            set_dscp  => '0x01',
            dport      => '997',
            chain     => 'OUTPUT',
            table     => 'mangle',
            provider  => 'ip6tables',
        }
        firewall { '1003 EF - set_dscp_class':
            proto          => 'tcp',
            jump           => 'DSCP',
            dport           => '997',
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
        firewall { '503 match_mark ip6tables - test':
          proto      => 'all',
          match_mark => '0x1',
          action     => reject,
          provider => 'ip6tables',
        }

      PUPPETCODE
      idempotent_apply(pp)
    end

    let(:result) { run_shell('ip6tables-save') }

    it 'physdev_in is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-in eth0 -m multiport --dports 701 -m comment --comment "701 - test" -j ACCEPT})
    end
    it 'physdev_out is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-out eth1 -m multiport --dports 702 -m comment --comment "702 - test" -j ACCEPT})
    end
    it 'physdev_in and physdev_out is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-in eth0 --physdev-out eth1 -m multiport --dports 703 -m comment --comment "703 - test" -j ACCEPT})
    end
    it 'physdev_is_bridged is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-is-bridged -m multiport --dports 704 -m comment --comment "704 - test" -j ACCEPT})
    end
    it 'physdev_in and physdev_is_bridged is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-in eth0 --physdev-is-bridged -m multiport --dports 705 -m comment --comment "705 - test" -j ACCEPT})
    end
    it 'physdev_out and physdev_is_bridged is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-out eth1 --physdev-is-bridged -m multiport --dports 706 -m comment --comment "706 - test" -j ACCEPT})
    end
    it 'physdev_in and physdev_out and physdev_is_bridged is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-in eth0 --physdev-out eth1 --physdev-is-bridged -m multiport --dports 707 -m comment --comment "707 - test" -j ACCEPT})
    end
    it 'physdev_is_in is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-is-in -m multiport --dports 708 -m comment --comment "708 - test" -j ACCEPT})
    end
    it 'physdev_is_out is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-is-out -m multiport --dports 709 -m comment --comment "709 - test" -j ACCEPT})
    end
    it 'set_dscp is set' do
      expect(result.stdout).to match(%r{-A OUTPUT -p tcp -m multiport --dports 997 -m comment --comment "1002 - set_dscp" -j DSCP --set-dscp 0x01})
    end
    it 'set_dscp_class is set' do
      expect(result.stdout).to match(%r{-A OUTPUT -p tcp -m multiport --dports 997 -m comment --comment "1003 EF - set_dscp_class" -j DSCP --set-dscp 0x2e})
    end
    it 'set_mss and mss is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1541 -m comment --comment "502 - set_mss" -j TCPMSS --set-mss 1360})
    end
    it 'clamp_mss_to_pmtu is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "503 - clamp_mss_to_pmtu" -j TCPMSS --clamp-mss-to-pmtu})
    end
    it 'hashlimit_name set to "upto-ip6"' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m hashlimit --hashlimit-upto 16\/sec --hashlimit-burst 640 --hashlimit-name upto-ip6 --hashlimit-htable-size 1310000 --hashlimit-htable-max 320000 --hashlimit-htable-expire 36000000 -m comment --comment "803 - hashlimit_upto test ip6" -j ACCEPT}) # rubocop:disable Layout/LineLength : Cannot reduce line to required length
    end
    it 'match_mark is set' do
      expect(result.stdout).to match(%r{-A INPUT -m mark --mark 0x1 -m comment --comment "503 match_mark ip6tables - test" -j REJECT --reject-with icmp6-port-unreachable})
    end
  end

  describe 'ishasmorefrags/islastfrag/isfirstfrag', unless: (os[:family] == 'redhat' && os[:release].start_with?('5', '6')) || (os[:family] == 'sles') do
    shared_examples 'is idempotent' do |values, line_match|
      pp2 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '599 - test':
              ensure   => present,
              proto    => 'tcp',
              provider => 'ip6tables',
              #{values}
            }
      PUPPETCODE
      it "changes the values to #{values}" do
        idempotent_apply(pp2)

        run_shell('ip6tables-save') do |r|
          expect(r.stdout).to match(%r{#{line_match}})
        end
      end
    end
    shared_examples "doesn't change" do |values, line_match|
      pp3 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '599 - test':
              ensure   => present,
              proto    => 'tcp',
              provider => 'ip6tables',
              #{values}
            }
      PUPPETCODE
      it "doesn't change the values to #{values}" do
        apply_manifest(pp3, catch_changes: true)

        run_shell('ip6tables-save') do |r|
          expect(r.stdout).to match(%r{#{line_match}})
        end
      end
    end

    describe 'adding a rule' do
      context 'when unset' do
        before :all do
          ip6tables_flush_all_tables
        end
        it_behaves_like 'is idempotent', '', %r{-A INPUT -p tcp -m comment --comment "599 - test"}
      end
      context 'when set to true' do
        before :all do
          ip6tables_flush_all_tables
        end
        it_behaves_like 'is idempotent', 'ishasmorefrags => true, islastfrag => true, isfirstfrag => true',
                        %r{-A INPUT -p tcp -m frag --fragid 0 --fragmore -m frag --fragid 0 --fraglast -m frag --fragid 0 --fragfirst -m comment --comment "599 - test"}
      end
      context 'when set to false' do
        before :all do
          ip6tables_flush_all_tables
        end
        it_behaves_like 'is idempotent', 'ishasmorefrags => false, islastfrag => false, isfirstfrag => false', %r{-A INPUT -p tcp -m comment --comment "599 - test"}
      end
    end
    describe 'editing a rule' do
      context 'when unset or false' do
        before :each do
          ip6tables_flush_all_tables
          run_shell('ip6tables -A INPUT -p tcp -m comment --comment "599 - test"')
        end
        context 'when current value is false' do
          it_behaves_like "doesn't change", 'ishasmorefrags => false, islastfrag => false, isfirstfrag => false', %r{-A INPUT -p tcp -m comment --comment "599 - test"}
        end
        context 'when current value is true' do
          it_behaves_like 'is idempotent', 'ishasmorefrags => true, islastfrag => true, isfirstfrag => true',
                          %r{-A INPUT -p tcp -m frag --fragid 0 --fragmore -m frag --fragid 0 --fraglast -m frag --fragid 0 --fragfirst -m comment --comment "599 - test"}
        end
      end
      context 'when set to true' do
        before :each do
          ip6tables_flush_all_tables
          run_shell('ip6tables -A INPUT -p tcp -m frag --fragid 0 --fragmore -m frag --fragid 0 --fraglast -m frag --fragid 0 --fragfirst -m comment --comment "599 - test"')
        end
        context 'when current value is false' do
          it_behaves_like 'is idempotent', 'ishasmorefrags => false, islastfrag => false, isfirstfrag => false', %r{-A INPUT -p tcp -m comment --comment "599 - test"}
        end
        context 'when current value is true' do
          it_behaves_like "doesn't change", 'ishasmorefrags => true, islastfrag => true, isfirstfrag => true',
                          %r{-A INPUT -p tcp -m frag --fragid 0 --fragmore -m frag --fragid 0 --fraglast -m frag --fragid 0 --fragfirst -m comment --comment "599 - test"}
        end
      end
    end
  end

  describe 'purge' do
    context 'when ipv6 chain purge', unless: os[:family] == 'redhat' && os[:release].start_with?('5') do
      after(:all) do
        ip6tables_flush_all_tables
      end
      before(:each) do
        ip6tables_flush_all_tables

        run_shell('ip6tables -A INPUT -p tcp -s 1::42')
        run_shell('ip6tables -A INPUT -p udp -s 1::42')
        run_shell('ip6tables -A OUTPUT -s 1::50 -m comment --comment "010 output-1::50"')
      end

      let(:result) { run_shell('ip6tables-save') }

      pp1 = <<-PUPPETCODE
            class { 'firewall': }
            firewallchain { 'INPUT:filter:IPv6':
              purge => true,
            }
        PUPPETCODE
      it 'purges only the specified chain' do
        apply_manifest(pp1, expect_changes: true)

        expect(result.stdout).to match(%r{010 output-1::50})
        expect(result.stdout).not_to match(%r{1::42})
        expect(result.stderr).to eq('')
      end

      pp2 = <<-PUPPETCODE
            class { 'firewall': }
            firewallchain { 'OUTPUT:filter:IPv6':
              purge => true,
            }
            firewall { '010 output-1::50':
              chain    => 'OUTPUT',
              proto    => 'all',
              source   => '1::50',
              provider => 'ip6tables',
            }
        PUPPETCODE
      it 'ignores managed rules' do
        apply_manifest(pp2, catch_changes: true)
      end

      pp3 = <<-PUPPETCODE
            class { 'firewall': }
            firewallchain { 'INPUT:filter:IPv6':
              purge => true,
              ignore => [
                '-s 1::42',
              ],
            }
        PUPPETCODE
      it 'ignores specified rules' do
        apply_manifest(pp3, catch_changes: true)
      end

      pp4 = <<-PUPPETCODE
            class { 'firewall': }
            firewallchain { 'INPUT:filter:IPv6':
              purge => true,
              ignore => [
                '-s 1::42',
              ],
            }
            firewall { '014 input-1::46':
              chain    => 'INPUT',
              proto    => 'all',
              source   => '1::46',
              provider => 'ip6tables',
            }
            -> firewall { '013 input-1::45':
              chain    => 'INPUT',
              proto    => 'all',
              source   => '1::45',
              provider => 'ip6tables',
            }
            -> firewall { '012 input-1::44':
              chain    => 'INPUT',
              proto    => 'all',
              source   => '1::44',
              provider => 'ip6tables',
            }
            -> firewall { '011 input-1::43':
              chain    => 'INPUT',
              proto    => 'all',
              source   => '1::43',
              provider => 'ip6tables',
            }
        PUPPETCODE
      it 'adds managed rules with ignored rules' do
        apply_manifest(pp4, catch_failures: true)

        expect(result.stdout).to match(%r{-A INPUT -s 1::42(\/128)? -p tcp\s?\n-A INPUT -s 1::42(\/128)? -p udp})
      end
    end
  end
end
