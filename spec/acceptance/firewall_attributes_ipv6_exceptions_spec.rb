# frozen_string_literal: true

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

  describe 'standard attributes', unless: os[:family] == 'sles' do
    describe 'dst_range' do
      context 'when 2001::db8::1-2001:db8::ff' do
        pp = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '602 - test':
            proto     => tcp,
            dport      => '602',
            jump      => accept,
            protocol  => 'ip6tables',
            dst_range => '2001::db8::1-2001:db8::ff',
          }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{Invalid IP address `2001::db8::1` in range `2001::db8::1-2001:db8::ff`})
          end
        end

        it 'does not contain the rule' do
          run_shell('ip6tables-save') do |r|
            expect(r.stdout).not_to match(%r{-A INPUT -p (tcp|6) -m iprange --dst-range 2001::db8::1-2001:db8::ff -m multiport --ports 602 -m comment --comment "602 - test" -j ACCEPT})
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
                jump     => accept,
                #{type}  => 'BROKEN',
                protocol => 'IPv6',
              }
          PUPPETCODE
          it 'fails' do
            apply_manifest(pp, expect_failures: true) do |r|
              expect(r.stderr).to match(%r{Error: Parameter #{type} failed})
            end
          end

          it 'does not contain the rule' do
            run_shell('ip6tables-save') do |r|
              expect(r.stdout).not_to match(%r{-A INPUT -p (tcp|6) -m addrtype\s.*\sBROKEN -m comment --comment "603 - test" -j ACCEPT})
            end
          end
        end

        context 'when duplicated LOCAL' do
          pp = <<-PUPPETCODE
                class { '::firewall': }
                firewall { '619 - test':
                  proto    => tcp,
                  jump     => accept,
                  #{type}  => ['LOCAL', 'LOCAL'],
                  protocol => 'IPv6',
                }
          PUPPETCODE
          it 'fails' do
            apply_manifest(pp, expect_failures: true) do |r|
              expect(r.stderr).to match(%r{`#{type}` elements must be unique})
            end
          end

          it 'does not contain the rule' do
            run_shell('ip6tables-save') do |r|
              expect(r.stdout).not_to match(%r{-A INPUT -p (tcp|6) -m addrtype\s.*\sLOCAL -m addrtype\s.*\sLOCAL -m comment --comment "619 - test" -j ACCEPT})
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
              jump   => accept,
              hop_limit => 'invalid',
              protocol => 'IPv6',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{Error: Parameter hop_limit failed})
          end
        end

        it 'does not contain the rule' do
          run_shell('ip6tables-save') do |r|
            expect(r.stdout).not_to match(%r{-A INPUT -p (tcp|6)-m tcp --dport 571 -m comment --comment "571 - test" -m hl --hl-eq invalid -j ACCEPT})
          end
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
            jump      => accept,
            protocol  => 'ip6tables',
            src_range => '2001::db8::1-2001:db8::ff',
          }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{Invalid IP address `2001::db8::1` in range `2001::db8::1-2001:db8::ff`})
          end
        end

        it 'does not contain the rule' do
          run_shell('ip6tables-save') do |r|
            expect(r.stdout).not_to match(%r{-A INPUT -p (tcp|6) -m iprange --src-range 2001::db8::1-2001:db8::ff-m tcp --dport 601 -m comment --comment "601 - test" -j ACCEPT})
          end
        end
      end
    end

    unless os[:family] == 'redhat' && os[:release].start_with?('8', '9')
      describe 'time tests' do
        context 'when set all time parameters' do
          pp1 = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '805 - time':
                proto              => tcp,
                dport              => '8080',
                jump               => accept,
                chain              => 'OUTPUT',
                date_start         => '2016-01-19T04:17:07',
                date_stop          => '2038-01-19T04:17:07',
                time_start         => '6:00',
                time_stop          => '17:00:00',
                month_days         => 7,
                week_days          => 'Tue',
                kernel_timezone    => true,
                protocol           => 'ip6tables',
              }
          PUPPETCODE
          it 'applies' do
            idempotent_apply(pp1)
          end

          it 'contains the rule' do
            run_shell('ip6tables-save') do |r|
              expect(r.stdout).to match(
                %r{-A OUTPUT -p (tcp|6) -m tcp --dport 8080 -m time --timestart 06:00:00 --timestop 17:00:00 --monthdays 7 --weekdays Tue --datestart 2016-01-19T04:17:07 --datestop 2038-01-19T04:17:07 --kerneltz -m comment --comment "805 - time" -j ACCEPT}, # rubocop:disable Layout/LineLength
              )
            end
          end
        end
      end
    end
  end

  describe 'happy path' do
    before(:all) do
      pp = <<-PUPPETCODE
        firewall { '701 - test':
          protocol   => 'ip6tables',
          chain      => 'FORWARD',
          proto      => tcp,
          dport      => '701',
          jump       => accept,
          physdev_in => 'eth0',
        }
        firewall { '702 - test':
          protocol    => 'ip6tables',
          chain       => 'FORWARD',
          proto       => tcp,
          dport       => '702',
          jump        => accept,
          physdev_out => 'eth1',
        }
        firewall { '703 - test':
          protocol => 'IPv6',
          chain       => 'FORWARD',
          proto       => tcp,
          dport       => '703',
          jump        => accept,
          physdev_in  => 'eth0',
          physdev_out => 'eth1',
        }
        firewall { '704 - test':
          protocol => 'IPv6',
          chain    => 'FORWARD',
          proto    => tcp,
          dport    => '704',
          jump     => accept,
          physdev_is_bridged => true,
        }
        firewall { '705 - test':
          protocol   => 'ip6tables',
          chain      => 'FORWARD',
          proto      => tcp,
          dport      => '705',
          jump       => accept,
          physdev_in => 'eth0',
          physdev_is_bridged => true,
        }
        firewall { '706 - test':
          protocol    => 'ip6tables',
          chain       => 'FORWARD',
          proto       => tcp,
          dport       => '706',
          jump        => accept,
          physdev_out => 'eth1',
          physdev_is_bridged => true,
        }
        firewall { '707 - test':
          protocol    => 'ip6tables',
          chain       => 'FORWARD',
          proto       => tcp,
          dport       => '707',
          jump        => accept,
          physdev_in  => 'eth0',
          physdev_out => 'eth1',
          physdev_is_bridged => true,
        }
        firewall { '708 - test':
          protocol      => 'ip6tables',
          chain         => 'FORWARD',
          proto         => tcp,
          dport         => '708',
          jump          => accept,
          physdev_is_in => true,
        }
        firewall { '709 - test':
          protocol       => 'ip6tables',
          chain          => 'FORWARD',
          proto          => tcp,
          dport          => '709',
          jump           => accept,
          physdev_is_out => true,
        }
        firewall { '1002 - set_dscp':
            proto     => 'tcp',
            jump      => 'DSCP',
            set_dscp  => '0x01',
            dport     => '997',
            chain     => 'OUTPUT',
            table     => 'mangle',
            protocol  => 'ip6tables',
        }
        firewall { '1003 EF - set_dscp_class':
            proto          => 'tcp',
            jump           => 'DSCP',
            dport          => '997',
            set_dscp_class => 'ef',
            chain          => 'OUTPUT',
            table          => 'mangle',
            protocol       => 'ip6tables',
        }
        firewall { '502 - set_mss':
            proto     => 'tcp',
            tcp_flags => 'SYN,RST SYN',
            jump      => 'TCPMSS',
            set_mss   => 1360,
            mss       => '1361:1541',
            chain     => 'FORWARD',
            table     => 'mangle',
            protocol  => 'ip6tables',
        }
        firewall { '503 - clamp_mss_to_pmtu':
            proto             => 'tcp',
            chain             => 'FORWARD',
            tcp_flags         => 'SYN,RST SYN',
            jump              => 'TCPMSS',
            clamp_mss_to_pmtu => true,
            protocol          => 'ip6tables',
        }
        firewall { '803 - hashlimit_upto test ip6':
          chain                   => 'INPUT',
          protocol                => 'ip6tables',
          hashlimit_name          => 'upto-ip6',
          hashlimit_upto          => '16/sec',
          hashlimit_burst         => 640,
          hashlimit_htable_size   => 1000000,
          hashlimit_htable_max    => 320000,
          hashlimit_htable_expire => 36000000,
          jump                    => accept,
        }
        firewall { '503 match_mark ip6tables - test':
          proto      => 'all',
          match_mark => '0x1',
          jump       => reject,
          protocol   => 'ip6tables',
        }

      PUPPETCODE
      idempotent_apply(pp)
    end

    let(:result) { run_shell('ip6tables-save') }

    it 'physdev_in is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p (tcp|6) -m physdev\s+--physdev-in eth0 -m tcp --dport 701 -m comment --comment "701 - test" -j ACCEPT})
    end

    it 'physdev_out is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p (tcp|6) -m physdev\s+--physdev-out eth1 -m tcp --dport 702 -m comment --comment "702 - test" -j ACCEPT})
    end

    it 'physdev_in and physdev_out is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p (tcp|6) -m physdev\s+--physdev-in eth0 --physdev-out eth1 -m tcp --dport 703 -m comment --comment "703 - test" -j ACCEPT})
    end

    it 'physdev_is_bridged is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p (tcp|6) -m physdev\s+--physdev-is-bridged -m tcp --dport 704 -m comment --comment "704 - test" -j ACCEPT})
    end

    it 'physdev_in and physdev_is_bridged is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p (tcp|6) -m physdev\s+--physdev-in eth0 --physdev-is-bridged -m tcp --dport 705 -m comment --comment "705 - test" -j ACCEPT})
    end

    it 'physdev_out and physdev_is_bridged is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p (tcp|6) -m physdev\s+--physdev-out eth1 --physdev-is-bridged -m tcp --dport 706 -m comment --comment "706 - test" -j ACCEPT})
    end

    it 'physdev_in and physdev_out and physdev_is_bridged is set' do
      expect(result.stdout).to match(
        %r{-A FORWARD -p (tcp|6) -m physdev\s+--physdev-in eth0 --physdev-out eth1 --physdev-is-bridged -m tcp --dport 707 -m comment --comment "707 - test" -j ACCEPT},
      )
    end

    it 'physdev_is_in is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p (tcp|6) -m physdev\s+--physdev-is-in -m tcp --dport 708 -m comment --comment "708 - test" -j ACCEPT})
    end

    it 'physdev_is_out is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p (tcp|6) -m physdev\s+--physdev-is-out -m tcp --dport 709 -m comment --comment "709 - test" -j ACCEPT})
    end

    it 'set_dscp is set' do
      expect(result.stdout).to match(%r{-A OUTPUT -p (tcp|6) -m tcp --dport 997 -m comment --comment "1002 - set_dscp" -j DSCP --set-dscp 0x01})
    end

    it 'set_dscp_class is set' do
      expect(result.stdout).to match(%r{-A OUTPUT -p (tcp|6) -m tcp --dport 997 -m comment --comment "1003 EF - set_dscp_class" -j DSCP --set-dscp 0x2e})
    end

    it 'set_mss and mss is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p (tcp|6) -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1541 -m comment --comment "502 - set_mss" -j TCPMSS --set-mss 1360})
    end

    it 'clamp_mss_to_pmtu is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p (tcp|6) -m tcp --tcp-flags SYN,RST SYN -m comment --comment "503 - clamp_mss_to_pmtu" -j TCPMSS --clamp-mss-to-pmtu})
    end

    it 'hashlimit_name set to "upto-ip6"' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m hashlimit --hashlimit-upto 16/sec --hashlimit-burst 640 --hashlimit-name upto-ip6 --hashlimit-htable-size 1000000 --hashlimit-htable-max 320000 --hashlimit-htable-expire 36000000 -m comment --comment "803 - hashlimit_upto test ip6" -j ACCEPT}) # rubocop:disable Layout/LineLength : Cannot reduce line to required length
    end

    it 'match_mark is set' do
      expect(result.stdout).to match(%r{-A INPUT -m mark --mark 0x1 -m comment --comment "503 match_mark ip6tables - test" -j REJECT --reject-with icmp6-port-unreachable})
    end
  end

  describe 'ishasmorefrags/islastfrag/isfirstfrag', unless: os[:family] == 'sles' do
    shared_examples 'is idempotent' do |values, line_match|
      pp2 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '599 - test':
              ensure   => present,
              proto    => 'tcp',
              protocol => 'IPv6',
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
              protocol => 'IPv6',
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

        it_behaves_like 'is idempotent', '', %r{-A INPUT -p (tcp|6) -m comment --comment "599 - test"}
      end

      context 'when set to true' do
        before :all do
          ip6tables_flush_all_tables
        end

        it_behaves_like 'is idempotent', 'ishasmorefrags => true, islastfrag => true, isfirstfrag => true',
                        %r{-A INPUT -p (tcp|6) -m frag --fragid 0 --fragmore -m frag --fragid 0 --fraglast -m frag --fragid 0 --fragfirst -m comment --comment "599 - test"}
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
          it_behaves_like "doesn't change", 'ishasmorefrags => false, islastfrag => false, isfirstfrag => false', %r{-A INPUT -p (tcp|6) -m comment --comment "599 - test"}
        end

        context 'when current value is true' do
          it_behaves_like 'is idempotent', 'ishasmorefrags => true, islastfrag => true, isfirstfrag => true',
                          %r{-A INPUT -p (tcp|6) -m frag --fragid 0 --fragmore -m frag --fragid 0 --fraglast -m frag --fragid 0 --fragfirst -m comment --comment "599 - test"}
        end
      end

      context 'when set to true' do
        before :each do
          ip6tables_flush_all_tables
          run_shell('ip6tables -A INPUT -p tcp -m frag --fragid 0 --fragmore -m frag --fragid 0 --fraglast -m frag --fragid 0 --fragfirst -m comment --comment "599 - test"')
        end

        context 'when current value is false' do
          it_behaves_like 'is idempotent', 'ishasmorefrags => false, islastfrag => false, isfirstfrag => false', %r{-A INPUT -p (tcp|6) -m comment --comment "599 - test"}
        end

        context 'when current value is true' do
          it_behaves_like "doesn't change", 'ishasmorefrags => true, islastfrag => true, isfirstfrag => true',
                          %r{-A INPUT -p (tcp|6) -m frag --fragid 0 --fragmore -m frag --fragid 0 --fraglast -m frag --fragid 0 --fragfirst -m comment --comment "599 - test"}
        end
      end
    end
  end

  describe 'purge' do
    context 'when ipv6 chain purge' do
      after(:all) do
        ip6tables_flush_all_tables
      end

      before(:each) do
        ip6tables_flush_all_tables

        run_shell('ip6tables -A INPUT -p tcp -s 1::42')
        run_shell('ip6tables -A INPUT -p udp -s 1::42')
        run_shell('ip6tables -A INPUT -s 1::49 -m comment --comment "009 output-1::49"')
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
      end

      pp2 = <<-PUPPETCODE
              class { 'firewall': }
              firewallchain { 'INPUT:filter:IPv6':
                purge => true,
              }
              firewall { '009 input-1::49':
                chain    => 'INPUT',
                proto    => 'all',
                source   => '1::49',
                protocol => 'IPv6',
              }
      PUPPETCODE
      it 'ignores managed rules' do
        apply_manifest(pp2, expect_changes: true)

        expect(result.stdout).not_to match(%r{-s 1::42(/128)?})
        expect(result.stdout).to match(%r{"009 input-1::49"})
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
        apply_manifest(pp3, expect_changes: true)

        expect(result.stdout).to match(%r{-A INPUT -s 1::42(/128)? -p (tcp|6)\s?\n-A INPUT -s 1::42(/128)? -p (udp|17)})
        expect(result.stdout).not_to match(%r{009 output-1::49})
      end

      pp4 = <<-PUPPETCODE
              class { 'firewall': }
              firewallchain { 'INPUT:filter:IPv6':
                purge => true,
                ignore_foreign => true,
              }
      PUPPETCODE
      it 'ignores foreign rules' do
        apply_manifest(pp4, expect_changes: true)

        expect(result.stdout).to match(%r{-A INPUT -s 1::42(/128)? -p (tcp|6)\s?\n-A INPUT -s 1::42(/128)? -p (udp|17)})
        expect(result.stdout).not_to match(%r{009 output-1::49})
      end

      pp5 = <<-PUPPETCODE
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
                protocol => 'IPv6',
              }
              -> firewall { '013 input-1::45':
                chain    => 'INPUT',
                proto    => 'all',
                source   => '1::45',
                protocol => 'IPv6',
              }
              -> firewall { '012 input-1::44':
                chain    => 'INPUT',
                proto    => 'all',
                source   => '1::44',
                protocol => 'IPv6',
              }
              -> firewall { '011 input-1::43':
                chain    => 'INPUT',
                proto    => 'all',
                source   => '1::43',
                protocol => 'IPv6',
              }
      PUPPETCODE
      it 'adds managed rules with ignored rules' do
        apply_manifest(pp5, catch_failures: true)

        expect(result.stdout).to match(%r{-A INPUT -s 1::42(/128)? -p (tcp|6)\s?\n-A INPUT -s 1::42(/128)? -p (udp|17)})
      end
    end
  end
end
