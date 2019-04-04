require 'spec_helper_acceptance'

describe 'firewall basics', docker: true do
  before :all do
    iptables_flush_all_tables
    ip6tables_flush_all_tables
  end

  # --bytecode is only supported by operatingsystems using nftables (in general Linux kernel 3.13, RedHat 7 (and derivates) with 3.10)
  # Skipping those from which we know they would fail.
  describe 'bytecode property', unless: (os[:family] == 'redhat' && os[:release][0] <= '6') ||
                                        (os[:family] == 'sles' && os[:release][0..1] <= '11') ||
                                        (host_inventory['facter']['os']['name'].casecmp('oraclelinux').zero? && os[:release][0] <= '7') do
    describe 'bytecode' do
      context '4,48 0 0 9,21 0 1 6,6 0 0 1,6 0 0 0' do
        pp = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '102 - test':
              action   => 'accept',
              bytecode => '4,48 0 0 9,21 0 1 6,6 0 0 1,6 0 0 0',
              chain    => 'OUTPUT',
              proto    => 'all',
              table    => 'filter',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp, catch_failures: true)
        end

        it 'contains the rule' do
          shell('iptables-save') do |r|
            expect(r.stdout).to match(%r{-A OUTPUT -m bpf --bytecode "4,48 0 0 9,21 0 1 6,6 0 0 1,6 0 0 0" -m comment --comment "102 - test" -j ACCEPT})
          end
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

  describe 'isfragment' do
    describe 'adding a rule' do
      before(:all) do
        pp = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '803 - test':
            ensure => present,
            proto  => 'tcp',
          }
          firewall { '804 - test':
            ensure => present,
            proto  => 'tcp',
            isfragment => true,
          }
          firewall { '805 - test':
            ensure => present,
            proto  => 'tcp',
            isfragment => false,
          }
        PUPPETCODE
        apply_manifest(pp, catch_failures: true)
        apply_manifest(pp, catch_changes: do_catch_changes)
      end

      let(:result) { shell('iptables-save') }

      it 'when unset' do
        expect(result.stdout).to match(%r{-A INPUT -p tcp -m comment --comment "803 - test"})
      end
      it 'when set to true' do
        expect(result.stdout).to match(%r{-A INPUT -p tcp -f -m comment --comment "804 - test"})
      end
      it 'when set to false' do
        expect(result.stdout).to match(%r{-A INPUT -p tcp -m comment --comment "805 - test"})
      end
    end
    describe 'editing a rule and current value is false' do
      before(:all) do
        pp_idempotent = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '807 - test':
            ensure => present,
            proto  => 'tcp',
            isfragment => true,
          }
          firewall { '808 - test':
            ensure => present,
            proto  => 'tcp',
            isfragment => false,
          }
        PUPPETCODE

        pp_does_not_change = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '806 - test':
            ensure => present,
            proto  => 'tcp',
            isfragment => false,
          }
          firewall { '809 - test':
            ensure => present,
            proto  => 'tcp',
            isfragment => true,
          }
        PUPPETCODE

        shell('iptables -A INPUT -p tcp -m comment --comment "806 - test"')
        shell('iptables -A INPUT -p tcp -m comment --comment "807 - test"')
        shell('iptables -A INPUT -p tcp -f -m comment --comment "808 - test"')
        shell('iptables -A INPUT -p tcp -f -m comment --comment "809 - test"')

        apply_manifest(pp_idempotent, catch_failures: true)
        apply_manifest(pp_idempotent, catch_changes: do_catch_changes)

        apply_manifest(pp_does_not_change, catch_changes: do_catch_changes)
      end

      let(:result) { shell('iptables-save') }

      it 'when unset or false' do
        expect(result.stdout).to match(%r{-A INPUT -p tcp -m comment --comment "806 - test"})
      end
      it 'when unset or false and current value is true' do
        expect(result.stdout).to match(%r{-A INPUT -p tcp -f -m comment --comment "807 - test"})
      end
      it 'when set to true and current value is false' do
        expect(result.stdout).to match(%r{-A INPUT -p tcp -m comment --comment "808 - test"})
      end
      it 'when set to true and current value is true' do
        expect(result.stdout).to match(%r{-A INPUT -p tcp -f -m comment --comment "809 - test"})
      end
    end
  end

  # describe 'firewall isfragment property' do
  #   before :all do
  #     iptables_flush_all_tables
  #     ip6tables_flush_all_tables
  #   end

  #   shared_examples 'is idempotent' do |value, line_match|
  #     pp1 = <<-PUPPETCODE
  #           class { '::firewall': }
  #           firewall { '597 - test':
  #             ensure => present,
  #             proto  => 'tcp',
  #             #{value}
  #           }
  #     PUPPETCODE
  #     it "changes the value to #{value}" do
  #       apply_manifest(pp1, catch_failures: true)
  #       apply_manifest(pp1, catch_changes: do_catch_changes)

  #       shell('iptables-save') do |r|
  #         expect(r.stdout).to match(%r{#{line_match}})
  #       end
  #     end
  #   end

  #   shared_examples "doesn't change" do |value, line_match|
  #     pp2 = <<-PUPPETCODE
  #           class { '::firewall': }
  #           firewall { '597 - test':
  #             ensure => present,
  #             proto  => 'tcp',
  #             #{value}
  #           }
  #     PUPPETCODE
  #     it "doesn't change the value to #{value}" do
  #       apply_manifest(pp2, catch_changes: do_catch_changes)

  #       shell('iptables-save') do |r|
  #         expect(r.stdout).to match(%r{#{line_match}})
  #       end
  #     end
  #   end

  #   describe 'adding a rule' do
  #     context 'when unset' do
  #       before :all do
  #         iptables_flush_all_tables
  #       end
  #       it_behaves_like 'is idempotent', '', %r{-A INPUT -p tcp -m comment --comment "597 - test"}
  #     end
  #     context 'when set to true' do
  #       before :all do
  #         iptables_flush_all_tables
  #       end
  #       it_behaves_like 'is idempotent', 'isfragment => true,', %r{-A INPUT -p tcp -f -m comment --comment "597 - test"}
  #     end
  #     context 'when set to false' do
  #       before :all do
  #         iptables_flush_all_tables
  #       end
  #       it_behaves_like 'is idempotent', 'isfragment => false,', %r{-A INPUT -p tcp -m comment --comment "597 - test"}
  #     end
  #   end

  #   describe 'editing a rule and current value is false' do
  #     context 'when unset or false' do
  #       before :each do
  #         iptables_flush_all_tables
  #         shell('iptables -A INPUT -p tcp -m comment --comment "597 - test"')
  #       end
  #       it_behaves_like "doesn't change", 'isfragment => false,', %r{-A INPUT -p tcp -m comment --comment "597 - test"}
  #     end
  #     context 'when unset or false and current value is true' do
  #       before :each do
  #         iptables_flush_all_tables
  #         shell('iptables -A INPUT -p tcp -m comment --comment "597 - test"')
  #       end
  #       it_behaves_like 'is idempotent', 'isfragment => true,', %r{-A INPUT -p tcp -f -m comment --comment "597 - test"}
  #     end

  #     context 'when set to true and current value is false' do
  #       before :each do
  #         iptables_flush_all_tables
  #         shell('iptables -A INPUT -p tcp -f -m comment --comment "597 - test"')
  #       end
  #       it_behaves_like 'is idempotent', 'isfragment => false,', %r{-A INPUT -p tcp -m comment --comment "597 - test"}
  #     end
  #     context 'when set to trueand current value is true' do
  #       before :each do
  #         iptables_flush_all_tables
  #         shell('iptables -A INPUT -p tcp -f -m comment --comment "597 - test"')
  #       end
  #       it_behaves_like "doesn't change", 'isfragment => true,', %r{-A INPUT -p tcp -f -m comment --comment "597 - test"}
  #     end
  #   end
  # end

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

  describe 'nflog', unless: fact('iptables_version') < '1.3.7' do
    describe 'nflog_group' do
      it 'applies' do
        pp2 = <<-PUPPETCODE
          class {'::firewall': }
          firewall { '503 - test': jump  => 'NFLOG', proto => 'all', nflog_group => 3}
        PUPPETCODE
        apply_manifest(pp2, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{NFLOG --nflog-group 3})
        end
      end
    end

    describe 'nflog_prefix' do
      it 'applies' do
        pp3 = <<-PUPPETCODE
        class {'::firewall': }
        firewall { '503 - test': jump  => 'NFLOG', proto => 'all', nflog_prefix => 'TEST PREFIX'}
        PUPPETCODE
        apply_manifest(pp3, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{NFLOG --nflog-prefix +"TEST PREFIX"})
        end
      end
    end

    describe 'nflog_range' do
      it 'applies' do
        pp4 = <<-PUPPETCODE
          class {'::firewall': }
          firewall { '503 - test': jump  => 'NFLOG', proto => 'all', nflog_range => 16}
        PUPPETCODE
        apply_manifest(pp4, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{NFLOG --nflog-range 16})
        end
      end
    end

    describe 'nflog_threshold' do
      it 'applies' do
        pp5 = <<-PUPPETCODE
          class {'::firewall': }
          firewall { '503 - test': jump  => 'NFLOG', proto => 'all', nflog_threshold => 2}
        PUPPETCODE
        apply_manifest(pp5, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{NFLOG --nflog-threshold 2})
        end
      end
    end

    describe 'multiple rules' do
      it 'applies' do
        pp6 = <<-PUPPETCODE
          class {'::firewall': }
          firewall { '503 - test': jump  => 'NFLOG', proto => 'all', nflog_threshold => 2, nflog_group => 3}
        PUPPETCODE
        apply_manifest(pp6, catch_failures: true)
      end

      it 'contains the rules' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{NFLOG --nflog-group 2 --nflog-threshold 3})
        end
      end
    end
  end

  describe 'nflog on older OSes', if: fact('iptables_version') < '1.3.7' do
    pp1 = <<-PUPPETCODE
        class {'::firewall': }
        firewall { '503 - test':
          jump  => 'NFLOG',
          proto => 'all',
          nflog_group => 3,
        }
    PUPPETCODE
    it 'throws an error' do
      apply_manifest(pp1, acceptable_error_codes: [0])
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

  describe 'purge tests' do
    before :all do
      iptables_flush_all_tables
      ip6tables_flush_all_tables
    end

    context 'when resources purge' do
      before(:all) do
        iptables_flush_all_tables

        shell('iptables -A INPUT -s 1.2.1.2')
        shell('iptables -A INPUT -s 1.2.1.2')
      end

      pp1 = <<-PUPPETCODE
          class { 'firewall': }
          resources { 'firewall':
            purge => true,
          }
      PUPPETCODE
      it 'make sure duplicate existing rules get purged' do
        apply_manifest(pp1, expect_changes: true)
      end

      it 'saves' do
        shell('iptables-save') do |r|
          expect(r.stdout).not_to match(%r{1\.2\.1\.2})
          expect(r.stderr).to eq('')
        end
      end
    end

    context 'when ipv4 chain purge' do
      after(:all) do
        iptables_flush_all_tables
      end
      before(:each) do
        iptables_flush_all_tables

        shell('iptables -A INPUT -p tcp -s 1.2.1.1')
        shell('iptables -A INPUT -p udp -s 1.2.1.1')
        shell('iptables -A OUTPUT -s 1.2.1.2 -m comment --comment "010 output-1.2.1.2"')
      end

      pp2 = <<-PUPPETCODE
          class { 'firewall': }
          firewallchain { 'INPUT:filter:IPv4':
            purge => true,
          }
      PUPPETCODE
      it 'purges only the specified chain' do
        apply_manifest(pp2, expect_changes: true)

        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{010 output-1\.2\.1\.2})
          expect(r.stdout).not_to match(%r{1\.2\.1\.1})
          expect(r.stderr).to eq('')
        end
      end
      # rubocop:enable RSpec/ExampleLength

      pp3 = <<-PUPPETCODE
          class { 'firewall': }
          firewallchain { 'OUTPUT:filter:IPv4':
            purge => true,
          }
          firewall { '010 output-1.2.1.2':
            chain  => 'OUTPUT',
            proto  => 'all',
            source => '1.2.1.2',
          }
      PUPPETCODE
      it 'ignores managed rules' do
        apply_manifest(pp3, catch_changes: do_catch_changes)
      end

      pp4 = <<-PUPPETCODE
          class { 'firewall': }
          firewallchain { 'INPUT:filter:IPv4':
            purge => true,
            ignore => [
              '-s 1\.2\.1\.1',
            ],
          }
      PUPPETCODE
      it 'ignores specified rules' do
        apply_manifest(pp4, catch_changes: do_catch_changes)
      end

      pp5 = <<-PUPPETCODE
          class { 'firewall': }
          firewallchain { 'INPUT:filter:IPv4':
            purge => true,
            ignore => [
              '-s 1\.2\.1\.1',
            ],
          }
          firewall { '014 input-1.2.1.6':
            chain  => 'INPUT',
            proto  => 'all',
            source => '1.2.1.6',
          }
          -> firewall { '013 input-1.2.1.5':
            chain  => 'INPUT',
            proto  => 'all',
            source => '1.2.1.5',
          }
          -> firewall { '012 input-1.2.1.4':
            chain  => 'INPUT',
            proto  => 'all',
            source => '1.2.1.4',
          }
          -> firewall { '011 input-1.2.1.3':
            chain  => 'INPUT',
            proto  => 'all',
            source => '1.2.1.3',
          }
      PUPPETCODE
      it 'adds managed rules with ignored rules' do
        apply_manifest(pp5, catch_failures: true)

        expect(shell('iptables-save').stdout).to match(%r{-A INPUT -s 1\.2\.1\.1(\/32)? -p tcp\s?\n-A INPUT -s 1\.2\.1\.1(\/32)? -p udp})
      end
    end
  end

  describe 'reset' do
    it 'deletes all rules' do
      shell('ip6tables --flush')
      shell('iptables --flush; iptables -t nat --flush; iptables -t mangle --flush')
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

  describe 'source' do
    describe 'when unmanaged rules exist' do
      pp1 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '101 test source changes':
              proto  => tcp,
              port   => '101',
              action => accept,
              source => '8.0.0.1',
            }
            firewall { '100 test source static':
              proto  => tcp,
              port   => '100',
              action => accept,
              source => '8.0.0.2',
            }
      PUPPETCODE
      it 'applies with 8.0.0.1 first' do
        apply_manifest(pp1, catch_failures: true)
      end

      it 'adds a unmanaged rule without a comment' do
        shell('iptables -A INPUT -t filter -s 8.0.0.3/32 -p tcp -m multiport --ports 102 -j ACCEPT')
        expect(shell('iptables-save').stdout).to match(%r{-A INPUT -s 8\.0\.0\.3(\/32)? -p tcp -m multiport --ports 102 -j ACCEPT})
      end

      it 'contains the changable 8.0.0.1 rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -s 8\.0\.0\.1(\/32)? -p tcp -m multiport --ports 101 -m comment --comment "101 test source changes" -j ACCEPT})
        end
      end
      it 'contains the static 8.0.0.2 rule' do # rubocop:disable RSpec/RepeatedExample : The values being matched differ
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -s 8\.0\.0\.2(\/32)? -p tcp -m multiport --ports 100 -m comment --comment "100 test source static" -j ACCEPT})
        end
      end

      pp2 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '101 test source changes':
              proto  => tcp,
              port   => '101',
              action => accept,
              source => '8.0.0.4',
            }
      PUPPETCODE
      it 'changes to 8.0.0.4 second' do
        expect(apply_manifest(pp2, catch_failures: true).stdout)
          .to match(%r{Notice: \/Stage\[main\]\/Main\/Firewall\[101 test source changes\]\/source: source changed '8\.0\.0\.1\/32' to '8\.0\.0\.4\/32'})
      end

      it 'does not contain the old changing 8.0.0.1 rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).not_to match(%r{8\.0\.0\.1})
        end
      end
      it 'contains the staic 8.0.0.2 rule' do # rubocop:disable RSpec/RepeatedExample : The values being matched differ
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -s 8\.0\.0\.2(\/32)? -p tcp -m multiport --ports 100 -m comment --comment "100 test source static" -j ACCEPT})
        end
      end
      it 'contains the changing new 8.0.0.4 rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -s 8\.0\.0\.4(\/32)? -p tcp -m multiport --ports 101 -m comment --comment "101 test source changes" -j ACCEPT})
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

  unless (os[:family] == 'redhat' && os[:release].start_with?('5', '6')) || (os[:family] == 'sles')
    describe 'ipvs' do
      context 'when set' do
        pp1 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '1002 - set ipvs':
              proto          => 'tcp',
              action         => accept,
              chain          => 'INPUT',
              ipvs           => true,
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp1, catch_failures: true)
        end

        it 'contains the rule' do
          shell('iptables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p tcp -m ipvs --ipvs -m comment --comment "1002 - set ipvs" -j ACCEPT})
          end
        end
      end
    end

    describe 'tee_gateway' do
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

    describe 'time tests' do
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

    # RHEL5/SLES does not support -m socket
    describe 'socket' do
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

      shared_examples 'is idempotent' do |value, line_match|
        pp1 = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '598 - test':
                ensure => present,
                proto  => 'tcp',
                chain  => 'PREROUTING',
                table  => 'raw',
                #{value}
              }
        PUPPETCODE
        it "changes the value to #{value}" do
          apply_manifest(pp1, catch_failures: true)
          apply_manifest(pp1, catch_changes: true)

          shell('iptables-save -t raw') do |r|
            expect(r.stdout).to match(%r{#{line_match}})
          end
        end
      end

      shared_examples "doesn't change" do |value, line_match|
        pp2 = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '598 - test':
                ensure => present,
                proto  => 'tcp',
                chain  => 'PREROUTING',
                table  => 'raw',
                #{value}
              }
        PUPPETCODE
        it "doesn't change the value to #{value}" do
          apply_manifest(pp2, catch_changes: true)

          shell('iptables-save -t raw') do |r|
            expect(r.stdout).to match(%r{#{line_match}})
          end
        end
      end

      describe 'adding a rule' do
        context 'when unset' do
          before :all do
            iptables_flush_all_tables
          end
          it_behaves_like 'is idempotent', '', %r{-A PREROUTING -p tcp -m comment --comment "598 - test"}
        end
        context 'when set to true' do
          before :all do
            iptables_flush_all_tables
          end
          it_behaves_like 'is idempotent', 'socket => true,', %r{-A PREROUTING -p tcp -m socket -m comment --comment "598 - test"}
        end
        context 'when set to false' do
          before :all do
            iptables_flush_all_tables
          end
          it_behaves_like 'is idempotent', 'socket => false,', %r{-A PREROUTING -p tcp -m comment --comment "598 - test"}
        end
      end

      describe 'editing a rule' do
        context 'when unset or false and current value is false' do
          before :each do
            iptables_flush_all_tables
            shell('iptables -t raw -A PREROUTING -p tcp -m comment --comment "598 - test"')
          end
          it_behaves_like "doesn't change", 'socket => false,', %r{-A PREROUTING -p tcp -m comment --comment "598 - test"}
        end
        context 'when unset or false and current value is true' do
          before :each do
            iptables_flush_all_tables
            shell('iptables -t raw -A PREROUTING -p tcp -m comment --comment "598 - test"')
          end
          it_behaves_like 'is idempotent', 'socket => true,', %r{-A PREROUTING -p tcp -m socket -m comment --comment "598 - test"}
        end
        context 'when set to true and current value is false' do
          before :each do
            iptables_flush_all_tables
            shell('iptables -t raw -A PREROUTING -p tcp -m socket -m comment --comment "598 - test"')
          end
          it_behaves_like 'is idempotent', 'socket => false,', %r{-A PREROUTING -p tcp -m comment --comment "598 - test"}
        end
        context 'when set to true and current value is true' do
          before :each do
            iptables_flush_all_tables
            shell('iptables -t raw -A PREROUTING -p tcp -m socket -m comment --comment "598 - test"')
          end
          it_behaves_like "doesn't change", 'socket => true,', %r{-A PREROUTING -p tcp -m socket -m comment --comment "598 - test"}
        end
      end
    end
  end

  # RHEL5 does not support --random
  unless os[:family] == 'redhat' && os[:release].start_with?('5')
    describe 'match_mark' do
      context 'when 0x1' do
        pp1 = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '503 match_mark - test':
                proto      => 'all',
                match_mark => '0x1',
                action     => reject,
              }
          PUPPETCODE
        it 'applies' do
          apply_manifest(pp1, catch_failures: true)
        end

        it 'contains the rule' do
          shell('iptables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -m mark --mark 0x1 -m comment --comment "503 match_mark - test" -j REJECT --reject-with icmp-port-unreachable})
          end
        end
      end
    end

    # iptables version 1.3.5 does not support masks on MARK rules
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

    describe 'random' do
      context 'when 192.168.1.1' do
        pp40 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '570 - random':
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
            expect(r.stdout).to match(%r{-A POSTROUTING -s 172\.30\.0\.0\/16 -m comment --comment "570 - random" -j MASQUERADE --random})
          end
        end
      end
    end
  end

  describe 'hashlimit', unless: ((os[:family] == 'redhat' && os[:release][0] <= '5')) do
    before(:all) do
      pp = <<-PUPPETCODE
        firewall { '805 - hashlimit_above test':
          chain                       => 'INPUT',
          proto                       => 'tcp',
          hashlimit_name              => 'above',
          hashlimit_above             => '526/sec',
          hashlimit_htable_gcinterval => '10',
          hashlimit_mode              => 'srcip,dstip',
          action                      => accept,
        }
        firewall { '806 - hashlimit_upto test':
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
      apply_manifest(pp, catch_failures: true)
      apply_manifest(pp, catch_changes: do_catch_changes)
    end

    let(:result) { shell('iptables-save') }

    it 'hashlimit_above is set' do
      regex_array = [%r{-A INPUT}, %r{-p tcp}, %r{--hashlimit-above 526\/sec}, %r{--hashlimit-mode srcip,dstip}, %r{--hashlimit-name above}, %r{--hashlimit-htable-gcinterval 10}, %r{-j ACCEPT}]

      regex_array.each do |regex|
        expect(result.stdout).to match(regex)
      end
    end
    it 'hashlimit_upto is set' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m hashlimit --hashlimit-upto 16\/sec --hashlimit-burst 640 --hashlimit-name upto --hashlimit-htable-size 1310000 --hashlimit-htable-max 320000 --hashlimit-htable-expire 36000000 -m comment --comment "806 - hashlimit_upto test" -j ACCEPT}) # rubocop:disable Metrics/LineLength : Cannot reduce line to required length
    end
  end
end
