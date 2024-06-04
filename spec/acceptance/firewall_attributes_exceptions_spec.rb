# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'firewall basics', docker: true do
  before :all do
    if os[:family] == 'ubuntu' || os[:family] == 'debian'
      update_profile_file
    elsif os[:family] == 'redhat'
      pre_setup
    end
    iptables_flush_all_tables
    ip6tables_flush_all_tables
    if os[:family] == 'debian' && os[:release] == '10'
      # in order to avoid this stderr: Warning: ip6tables-legacy tables present, use ip6tables-legacy-save to see them\n"
      run_shell('update-alternatives --set iptables /usr/sbin/iptables-legacy')
    end
  end

  # --bytecode is only supported by operatingsystems using nftables (in general Linux kernel 3.13, RedHat 7 (and derivates) with 3.10)
  # Skipping those from which we know they would fail.
  describe 'bytecode property', unless: (fetch_os_name == 'oraclelinux' && os[:release][0] == '7') ||
                                        (os[:family] == 'ubuntu') do
    describe 'bytecode' do
      context 'when 4,48 0 0 9,21 0 1 6,6 0 0 1,6 0 0 0' do
        pp = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '102 - test':
              jump     => 'accept',
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
          run_shell('iptables-save') do |r|
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
            jump   => accept,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp22, expect_failures: true) do |r|
          expect(r.stderr).to match(%r{invalid port/service `9999561' specified})
        end
      end

      it 'contains the rule' do
        run_shell('iptables-save') do |r|
          expect(r.stdout).not_to match(%r{-A INPUT -p (tcp|6) -m multiport --dports 9999561-562 -m comment --comment "560 - test" -j ACCEPT})
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
            dport   => '555',
            jump   => accept,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp4, catch_failures: true)
      end

      it 'contains the rule' do
        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -p (tcp|6) -m tcp --dport 555 -m comment --comment "555 - test" -j ACCEPT})
        end
      end
    end

    context 'when absent' do
      pp5 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '555 - test':
            ensure => absent,
            proto  => tcp,
            dport   => '555',
            jump   => accept,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp5, catch_failures: true)
      end

      it 'does not contain the rule' do
        run_shell('iptables-save') do |r|
          expect(r.stdout).not_to match(%r{-A INPUT -p (tcp|6) -m tcp --dport 555 -m comment --comment "555 - test" -j ACCEPT})
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

        idempotent_apply(pp)
      end

      let(:result) { run_shell('iptables-save') }

      it 'when unset' do
        expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m comment --comment "803 - test"})
      end

      it 'when set to true' do
        expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -f -m comment --comment "804 - test"})
      end

      it 'when set to false' do
        expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m comment --comment "805 - test"})
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

        run_shell('iptables -A INPUT -p tcp -m comment --comment "806 - test"')
        run_shell('iptables -A INPUT -p tcp -m comment --comment "807 - test"')
        run_shell('iptables -A INPUT -p tcp -f -m comment --comment "808 - test"')
        run_shell('iptables -A INPUT -p tcp -f -m comment --comment "809 - test"')

        idempotent_apply(pp_idempotent)
        apply_manifest(pp_does_not_change, catch_changes: true)
      end

      let(:result) { run_shell('iptables-save') }

      it 'when unset or false' do
        expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m comment --comment "806 - test"})
      end

      it 'when unset or false and current value is true' do
        expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -f -m comment --comment "807 - test"})
      end

      it 'when set to true and current value is false' do
        expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m comment --comment "808 - test"})
      end

      it 'when set to true and current value is true' do
        expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -f -m comment --comment "809 - test"})
      end
    end
  end

  describe 'firewall isfragment property' do
    before :all do
      iptables_flush_all_tables
      ip6tables_flush_all_tables
    end

    shared_examples 'is idempotent' do |value, line_match|
      pp1 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '597 - test':
              ensure => present,
              proto  => 'tcp',
              #{value}
            }
      PUPPETCODE
      it "changes the value to #{value}" do
        idempotent_apply(pp1)

        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{#{line_match}})
        end
      end
    end

    shared_examples "doesn't change" do |value, line_match|
      pp2 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '597 - test':
              ensure => present,
              proto  => 'tcp',
              #{value}
            }
      PUPPETCODE
      it "doesn't change the value to #{value}" do
        apply_manifest(pp2, catch_changes: true)

        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{#{line_match}})
        end
      end
    end

    describe 'adding a rule' do
      context 'when unset' do
        before :all do
          iptables_flush_all_tables
        end

        it_behaves_like 'is idempotent', '', %r{-A INPUT -p (tcp|6) -m comment --comment "597 - test"}
      end

      context 'when set to true' do
        before :all do
          iptables_flush_all_tables
        end

        it_behaves_like 'is idempotent', 'isfragment => true,', %r{-A INPUT -p (tcp|6) -f -m comment --comment "597 - test"}
      end

      context 'when set to false' do
        before :all do
          iptables_flush_all_tables
        end

        it_behaves_like 'is idempotent', 'isfragment => false,', %r{-A INPUT -p (tcp|6) -m comment --comment "597 - test"}
      end
    end

    describe 'editing a rule and current value is false' do
      context 'when unset or false' do
        before :each do
          iptables_flush_all_tables
          run_shell('iptables -A INPUT -p tcp -m comment --comment "597 - test"')
        end

        it_behaves_like "doesn't change", 'isfragment => false,', %r{-A INPUT -p (tcp|6) -m comment --comment "597 - test"}
      end

      context 'when unset or false and current value is true' do
        before :each do
          iptables_flush_all_tables
          run_shell('iptables -A INPUT -p tcp -m comment --comment "597 - test"')
        end

        it_behaves_like 'is idempotent', 'isfragment => true,', %r{-A INPUT -p (tcp|6) -f -m comment --comment "597 - test"}
      end

      context 'when set to true and current value is false' do
        before :each do
          iptables_flush_all_tables
          run_shell('iptables -A INPUT -p tcp -f -m comment --comment "597 - test"')
        end

        it_behaves_like 'is idempotent', 'isfragment => false,', %r{-A INPUT -p (tcp|6) -m comment --comment "597 - test"}
      end

      context 'when set to trueand current value is true' do
        before :each do
          iptables_flush_all_tables
          run_shell('iptables -A INPUT -p tcp -f -m comment --comment "597 - test"')
        end

        it_behaves_like "doesn't change", 'isfragment => true,', %r{-A INPUT -p (tcp|6) -f -m comment --comment "597 - test"}
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
        idempotent_apply(pp88)
      end

      it 'contains the rule' do
        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -s 10.1.5.28/(32|255\.255\.255\.255) -p (tcp|6) -m mac --mac-source 0(a|A):1(b|B):3(c|C):4(d|D):5(e|E):6(f|F) -m comment --comment "610 - test"})
        end
      end
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
          expect(r.stderr).to match(%r{Rule name cannot start with 9000-9999})
        end
      end
    end
  end

  describe 'nflog', unless: iptables_version < '1.3.7' do
    describe 'nflog_group' do
      it 'applies' do
        pp2 = <<-PUPPETCODE
          class {'::firewall': }
          firewall { '503 - test': jump  => 'NFLOG', proto => 'all', nflog_group => 3}
        PUPPETCODE
        apply_manifest(pp2, catch_failures: true)
      end

      it 'contains the rule' do
        run_shell('iptables-save') do |r|
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
        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{NFLOG --nflog-prefix +"TEST PREFIX"})
        end
      end
    end

    # --nflog-range was deprecated and replaced by --nflog-size in iptables 1.6.1
    describe 'nflog_range', unless: iptables_version > '1.6.0' do
      it 'applies' do
        pp4 = <<-PUPPETCODE
          class {'::firewall': }
          firewall { '503 - test': jump  => 'NFLOG', proto => 'all', nflog_range => 16}
        PUPPETCODE
        apply_manifest(pp4, catch_failures: true)
      end

      it 'contains the rule' do
        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{NFLOG --nflog-range 16})
        end
      end
    end

    describe 'nflog_size', unless: iptables_version < '1.6.1' do
      it 'applies' do
        pp4 = <<-PUPPETCODE
          class {'::firewall': }
          firewall { '503 - test': jump  => 'NFLOG', proto => 'all', nflog_size => 16}
        PUPPETCODE
        apply_manifest(pp4, catch_failures: true)
      end

      it 'contains the rule' do
        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{NFLOG --nflog-size 16})
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
        run_shell('iptables-save') do |r|
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
        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{NFLOG --nflog-group 3 --nflog-threshold 2})
        end
      end
    end
  end

  describe 'nflog on older OSes' do
    pp1 = <<-PUPPETCODE
        class {'::firewall': }
        firewall { '503 - test':
          jump  => 'NFLOG',
          proto => 'all',
          nflog_group => 3,
        }
    PUPPETCODE
    it 'throws an error' do
      res = apply_manifest(pp1)
      expect(res[:exit_code]).to be(0)
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

        run_shell('iptables -A INPUT -s 1.2.1.2')
        run_shell('iptables -A INPUT -s 1.2.1.2')
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
        run_shell('iptables-save') do |r|
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

        run_shell('iptables -A INPUT -p tcp -s 1.2.1.1')
        run_shell('iptables -A INPUT -p udp -s 1.2.1.1')
        run_shell('iptables -A INPUT -s 1.2.1.3 -m comment --comment "010 input-1.2.1.3"')
        run_shell('iptables -A OUTPUT -s 1.2.1.2 -m comment --comment "010 output-1.2.1.2"')
      end

      pp2 = <<-PUPPETCODE
          class { 'firewall': }
          firewallchain { 'INPUT:filter:IPv4':
            purge => true,
          }
      PUPPETCODE
      it 'purges only the specified chain' do
        apply_manifest(pp2, expect_changes: true)

        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{010 output-1\.2\.1\.2})
          expect(r.stdout).not_to match(%r{1\.2\.1\.(1|3)})
        end
      end

      pp3 = <<-PUPPETCODE
          class { 'firewall': }
          firewallchain { 'INPUT:filter:IPv4':
            purge => true,
          }
          firewall { '010 input-1.2.1.3':
            chain  => 'INPUT',
            proto  => 'all',
            source => '1.2.1.3',
          }
      PUPPETCODE
      it 'ignores managed rules' do
        apply_manifest(pp3, expect_changes: true)

        run_shell('iptables-save') do |r|
          expect(r.stdout).not_to match(%r{1\.2\.1\.1})
          expect(r.stdout).to match(%r{010 input-1\.2\.1\.3})
        end
      end

      pp4 = <<-PUPPETCODE
          class { 'firewall': }
          firewallchain { 'INPUT:filter:IPv4':
            purge => true,
            ignore => [
              '-s 1.2.1.1',
            ],
          }
      PUPPETCODE
      it 'ignores specified rules' do
        apply_manifest(pp4, expect_changes: true)

        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{1\.2\.1\.1})
          expect(r.stdout).not_to match(%r{010 input-1\.2\.1\.3})
        end
      end

      pp5 = <<-PUPPETCODE
          class { 'firewall': }
          firewallchain { 'INPUT:filter:IPv4':
            purge => true,
            ignore_foreign => true,
          }
      PUPPETCODE
      it 'ignores foreign rules' do
        apply_manifest(pp5, expect_changes: true)

        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{1\.2\.1\.1})
          expect(r.stdout).not_to match(%r{010 input-1\.2\.1\.3})
        end
      end

      pp6 = <<-PUPPETCODE
          class { 'firewall': }
          firewallchain { 'INPUT:filter:IPv4':
            purge => true,
            ignore => [
              '-s 1.2.1.1',
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
        apply_manifest(pp6, catch_failures: true)

        expect(run_shell('iptables-save').stdout).to match(%r{-A INPUT -s 1\.2\.1\.1(/32)? -p (tcp|6)\s?\n-A INPUT -s 1\.2\.1\.1(/32)? -p (udp|17)})
      end
    end
  end

  describe 'reset' do
    it 'deletes all rules' do
      run_shell('ip6tables --flush')
      run_shell('iptables --flush; iptables -t nat --flush; iptables -t mangle --flush')
    end
  end

  describe 'sport' do
    context 'when invalid ports' do
      pp19 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '560 - test':
            proto  => tcp,
            sport  => '9999560-561',
            jump   => accept,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp19, expect_failures: true) do |r|
          expect(r.stderr).to match(%r{invalid port/service `9999560' specified})
        end
      end

      it 'contains the rule' do
        run_shell('iptables-save') do |r|
          expect(r.stdout).not_to match(%r{-A INPUT -p (tcp|6) -m tcp --sport 9999560-561 -m comment --comment "560 - test" -j ACCEPT})
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
              dport   => '101',
              jump   => accept,
              source => '8.0.0.1',
            }
            firewall { '100 test source static':
              proto  => tcp,
              dport   => '100',
              jump   => accept,
              source => '8.0.0.2',
            }
      PUPPETCODE
      it 'applies with 8.0.0.1 first' do
        apply_manifest(pp1, catch_failures: true)
      end

      it 'adds a unmanaged rule without a comment' do
        run_shell('iptables -A INPUT -t filter -s 8.0.0.3/32 -p tcp -m multiport --dports 102 -j ACCEPT')
        expect(run_shell('iptables-save').stdout).to match(%r{-A INPUT -s 8\.0\.0\.3(/32)? -p (tcp|6) -m multiport --dports 102 -j ACCEPT})
      end

      it 'contains the changable 8.0.0.1 rule' do
        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -s 8\.0\.0\.1(/32)? -p (tcp|6) -m tcp --dport 101 -m comment --comment "101 test source changes" -j ACCEPT})
        end
      end

      it 'contains the static 8.0.0.2 rule' do # rubocop:disable RSpec/RepeatedExample : The values being matched differ
        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -s 8\.0\.0\.2(/32)? -p (tcp|6) -m tcp --dport 100 -m comment --comment "100 test source static" -j ACCEPT})
        end
      end

      pp2 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '101 test source changes':
              proto  => tcp,
              dport   => '101',
              jump   => accept,
              source => '8.0.0.4',
            }
      PUPPETCODE
      it 'changes to 8.0.0.4 second' do
        apply_manifest(pp2, catch_failures: true)
      end

      it 'does not contain the old changing 8.0.0.1 rule' do
        run_shell('iptables-save') do |r|
          expect(r.stdout).not_to match(%r{8\.0\.0\.1})
        end
      end

      it 'contains the staic 8.0.0.2 rule' do # rubocop:disable RSpec/RepeatedExample : The values being matched differ
        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -s 8\.0\.0\.2(/32)? -p (tcp|6) -m tcp --dport 100 -m comment --comment "100 test source static" -j ACCEPT})
        end
      end

      it 'contains the changing new 8.0.0.4 rule' do
        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -s 8\.0\.0\.4(/32)? -p (tcp|6) -m tcp --dport 101 -m comment --comment "101 test source changes" -j ACCEPT})
        end
      end
    end
  end

  ['dst_type', 'src_type'].each do |type|
    describe type.to_s do
      context 'when LOCAL --limit-iface-in' do
        pp97 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '613 - test':
              proto   => tcp,
              jump    => accept,
              #{type} => 'LOCAL --limit-iface-in',
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp97, catch_failures: true)
        end

        it 'contains the rule' do
          run_shell('iptables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p (tcp|6) -m addrtype\s.*\sLOCAL --limit-iface-in -m comment --comment "613 - test" -j ACCEPT})
          end
        end
      end

      context 'when duplicated LOCAL' do
        pp99 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '615 - test':
              proto   => tcp,
              jump    => accept,
              #{type} => ['LOCAL', 'LOCAL'],
            }
        PUPPETCODE
        it 'fails' do
          apply_manifest(pp99, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{`#{type}` elements must be unique})
          end
        end

        it 'does not contain the rule' do
          run_shell('iptables-save') do |r|
            expect(r.stdout).not_to match(%r{-A INPUT -p (tcp|6) -m addrtype --#{type.tr('_', '-')} LOCAL -m addrtype --#{type.tr('_', '-')} LOCAL -m comment --comment "615 - test" -j ACCEPT})
          end
        end
      end

      context 'when multiple addrtype' do
        pp100 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '616 - test':
              proto   => tcp,
              jump    => accept,
              #{type} => ['LOCAL', '! LOCAL'],
            }
        PUPPETCODE
        it 'applies' do
          apply_manifest(pp100, catch_failures: true)
        end

        it 'contains the rule' do
          run_shell('iptables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -p (tcp|6) -m addrtype --#{type.tr('_', '-')} LOCAL -m addrtype ! --#{type.tr('_', '-')} LOCAL -m comment --comment "616 - test" -j ACCEPT})
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
            jump   => accept,
            table  => 'mangle',
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp31, catch_failures: true)
      end

      it 'contains the rule' do
        run_shell('iptables-save -t mangle') do |r|
          expect(r.stdout).to match(%r{-A INPUT -p (tcp|6) -m comment --comment "566 - test" -j ACCEPT})
        end
      end
    end

    context 'when nat' do
      pp32 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '566 - test2':
            proto  => tcp,
            jump   => accept,
            table  => 'nat',
            chain  => 'OUTPUT',
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp32, catch_failures: true)
      end

      it 'does not contain the rule' do
        run_shell('iptables-save -t nat') do |r|
          expect(r.stdout).to match(%r{-A OUTPUT -p (tcp|6) -m comment --comment "566 - test2" -j ACCEPT})
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
        run_shell('iptables-save -t nat') do |r|
          expect(r.stdout).to match(%r{-A PREROUTING -s 200.200.200.200(/32)? -p (tcp|6) -m comment --comment "569 - test" -j NETMAP --to 192.168.1.1})
        end
      end
    end

    describe 'reset' do
      it 'deletes all rules' do
        run_shell('ip6tables --flush')
        run_shell('iptables --flush; iptables -t nat --flush; iptables -t mangle --flush')
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
        run_shell('iptables-save -t nat') do |r|
          expect(r.stdout).to match(%r{-A POSTROUTING -d 200.200.200.200(/32)? -p (tcp|6) -m comment --comment "569 - test" -j NETMAP --to 192.168.1.1})
        end
      end
    end
  end

  describe 'ipvs' do
    context 'when set' do
      pp1 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '1002 - set ipvs':
            proto          => 'tcp',
            jump           => accept,
            chain          => 'INPUT',
            ipvs           => true,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp1, catch_failures: true)
      end

      it 'contains the rule' do
        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -p (tcp|6) -m ipvs --ipvs -m comment --comment "1002 - set ipvs" -j ACCEPT})
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
        run_shell('iptables-save -t mangle') do |r|
          expect(r.stdout).to match(%r{-A PREROUTING -m comment --comment "810 - tee_gateway" -j TEE --gateway 10.0.0.2})
        end
      end
    end
  end

  unless (os[:family] == 'redhat' && os[:release].start_with?('8', '9')) || (os[:family] == 'sles')
    describe 'time tests' do
      context 'when set all time parameters' do
        pp1 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '805 - test':
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
            }
        PUPPETCODE
        it 'applies manifest twice' do
          idempotent_apply(pp1)
        end

        it 'contains the rule' do
          run_shell('iptables-save') do |r|
            expect(r.stdout).to match(
              %r{-A OUTPUT -p (tcp|6) -m tcp --dport 8080 -m time --timestart 06:00:00 --timestop 17:00:00 --monthdays 7 --weekdays Tue --datestart 2016-01-19T04:17:07 --datestop 2038-01-19T04:17:07 --kerneltz -m comment --comment "805 - test" -j ACCEPT}, # rubocop:disable Layout/LineLength
            )
          end
        end
      end
    end
  end

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
            protocol => iptables,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp38, catch_failures: true)
      end

      it 'contains the rule' do
        run_shell('iptables-save -t mangle') do |r|
          expect(r.stdout).to match(%r{-A POSTROUTING -o virbr0 -p (udp|17) -m udp --dport 68 -m comment --comment "576 - test" -j CHECKSUM --checksum-fill})
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
            dport   => '585',
            jump   => accept,
            chain  => 'PREROUTING',
            table  => 'nat',
            socket => true,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp78, catch_failures: true)
      end

      it 'contains the rule' do
        run_shell('iptables-save -t nat') do |r|
          expect(r.stdout).to match(%r{-A PREROUTING -p (tcp|6) -m tcp --dport 585 -m socket -m comment --comment "585 - test" -j ACCEPT})
        end
      end
    end

    context 'when false' do
      pp79 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '586 - test':
            ensure => present,
            proto => tcp,
            dport   => '586',
            jump   => accept,
            chain  => 'PREROUTING',
            table  => 'nat',
            socket => false,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp79, catch_failures: true)
      end

      it 'contains the rule' do
        run_shell('iptables-save -t nat') do |r|
          expect(r.stdout).to match(%r{-A PREROUTING -p (tcp|6) -m tcp --dport 586 -m comment --comment "586 - test" -j ACCEPT})
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
        # apply_manifest(pp1, catch_failures: true)
        apply_manifest(pp1, expect_changes: true)

        run_shell('iptables-save -t raw') do |r|
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
        apply_manifest(pp2)

        run_shell('iptables-save -t raw') do |r|
          expect(r.stdout).to match(%r{#{line_match}})
        end
      end
    end

    describe 'adding a rule' do
      context 'when unset' do
        before :all do
          iptables_flush_all_tables
        end

        it_behaves_like 'is idempotent', '', %r{-A PREROUTING -p (tcp|6) -m comment --comment "598 - test"}
      end

      context 'when set to true' do
        before :all do
          iptables_flush_all_tables
        end

        it_behaves_like 'is idempotent', 'socket => true,', %r{-A PREROUTING -p (tcp|6) -m socket -m comment --comment "598 - test"}
      end

      context 'when set to false' do
        before :all do
          iptables_flush_all_tables
        end

        it_behaves_like 'is idempotent', 'socket => false,', %r{-A PREROUTING -p (tcp|6) -m comment --comment "598 - test"}
      end
    end

    describe 'editing a rule' do
      context 'when unset or false and current value is false' do
        before :each do
          iptables_flush_all_tables
          run_shell('iptables -t raw -A PREROUTING -p tcp -m comment --comment "598 - test"')
        end

        it_behaves_like "doesn't change", 'socket => false,', %r{-A PREROUTING -p (tcp|6) -m comment --comment "598 - test"}
      end

      context 'when unset or false and current value is true' do
        before :each do
          iptables_flush_all_tables
          run_shell('iptables -t raw -A PREROUTING -p tcp -m comment --comment "598 - test"')
        end

        it_behaves_like 'is idempotent', 'socket => true,', %r{-A PREROUTING -p (tcp|6) -m socket -m comment --comment "598 - test"}
      end

      context 'when set to true and current value is false' do
        before :each do
          iptables_flush_all_tables
          run_shell('iptables -t raw -A PREROUTING -p tcp -m socket -m comment --comment "598 - test"')
        end

        it_behaves_like 'is idempotent', 'socket => false,', %r{-A PREROUTING -p (tcp|6) -m comment --comment "598 - test"}
      end

      context 'when set to true and current value is true' do
        before :each do
          iptables_flush_all_tables
          run_shell('iptables -t raw -A PREROUTING -p tcp -m socket -m comment --comment "598 - test"')
        end

        it_behaves_like "doesn't change", 'socket => true,', %r{-A PREROUTING -p (tcp|6) -m socket -m comment --comment "598 - test"}
      end
    end
  end

  describe 'match_mark' do
    context 'when 0x1' do
      pp1 = <<-PUPPETCODE
            class { '::firewall': }
            firewall { '503 match_mark - test':
              proto      => 'all',
              match_mark => '0x1',
              jump       => reject,
            }
            firewall { '504 match_mark - test with mask':
              proto      => 'all',
              match_mark => '0x1/0x2000',
              jump       => reject,
            }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp1, catch_failures: true)
      end

      it 'contains the rule' do
        run_shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A INPUT -m mark --mark 0x1 -m comment --comment "503 match_mark - test" -j REJECT --reject-with icmp-port-unreachable})
          expect(r.stdout).to match(%r{-A INPUT -m mark --mark 0x1/0x2000 -m comment --comment "504 match_mark - test with mask" -j REJECT --reject-with icmp-port-unreachable})
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
            dport   => '580',
            jump => 'MARK',
            table => 'mangle',
            set_mark => '0x3e8/0xffffffff',
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp73, catch_failures: true)
      end

      it 'contains the rule' do
        run_shell('iptables-save -t mangle') do |r|
          expect(r.stdout).to match(%r{-A OUTPUT -p (tcp|6) -m tcp --dport 580 -m comment --comment "580 - test" -j MARK --set-xmark 0x3e8/0xffffffff})
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
      it 'applies manifest twice' do
        idempotent_apply(pp40)
      end

      it 'contains the rule' do
        run_shell('iptables-save -t nat') do |r|
          expect(r.stdout).to match(%r{-A POSTROUTING -s 172\.30\.0\.0/16 -m comment --comment "570 - random" -j MASQUERADE --random})
        end
      end
    end
  end

  describe 'hashlimit' do
    before(:all) do
      pp = <<-PUPPETCODE
        firewall { '805 - hashlimit_above test':
          chain                       => 'INPUT',
          proto                       => 'tcp',
          hashlimit_name              => 'above',
          hashlimit_above             => '526/sec',
          hashlimit_htable_gcinterval => 10,
          hashlimit_mode              => 'srcip,dstip',
          jump                        => accept,
        }
        firewall { '806 - hashlimit_upto test':
          chain                   => 'INPUT',
          hashlimit_name          => 'upto',
          hashlimit_upto          => '16/sec',
          hashlimit_burst         => 640,
          hashlimit_htable_size   => 1000000,
          hashlimit_htable_max    => 320000,
          hashlimit_htable_expire => 36000000,
          jump                    => accept,
        }
      PUPPETCODE
      idempotent_apply(pp)
    end

    let(:result) { run_shell('iptables-save') }

    it 'hashlimit_above is set' do
      regex_array = [%r{-A INPUT}, %r{-p (tcp|6)}, %r{--hashlimit-above 526/sec}, %r{--hashlimit-mode srcip,dstip}, %r{--hashlimit-name above}, %r{--hashlimit-htable-gcinterval 10}, %r{-j ACCEPT}]

      regex_array.each do |regex|
        expect(result.stdout).to match(regex)
      end
    end

    it 'hashlimit_upto is set' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m hashlimit --hashlimit-upto 16/sec --hashlimit-burst 640 --hashlimit-name upto --hashlimit-htable-size 1000000 --hashlimit-htable-max 320000 --hashlimit-htable-expire 36000000 -m comment --comment "806 - hashlimit_upto test" -j ACCEPT}) # rubocop:disable Layout/LineLength : Cannot reduce line to required length
    end
  end

  describe 'random-fully', if: (os[:family] == 'redhat' && os[:release].start_with?('8', '9')) || (os[:family] == 'debian' && os[:release].start_with?('10', '11')) do
    before(:all) do
      pp = <<-PUPPETCODE
        firewall { '901 - set random-fully':
          table        => 'nat',
          chain        => 'POSTROUTING',
          jump         => 'MASQUERADE',
          random_fully => true,
        }
      PUPPETCODE
      idempotent_apply(pp)
    end

    let(:result) { run_shell('iptables-save') }

    it 'adds random-fully rule' do
      expect(result.stdout).to match(%r{-A POSTROUTING -p (tcp|6) -m comment --comment "901 - set random-fully" -j MASQUERADE --random-fully})
    end
  end

  describe 'condition', condition_parameter_test: false do
    context 'when is set' do
      pp = <<-PUPPETCODE
        if $facts['os']['name'] == 'Ubuntu' {
          firewall { '010 isblue ipv4':
            ensure    => 'present',
            condition => '! isblue',
            chain     => 'INPUT',
            iniface   => 'enp0s8',
            proto     => 'icmp',
            jump      => 'drop',
          }
        }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp)
      end

      if fetch_os_name == 'ubuntu'
        it 'contains the rule' do
          run_shell('iptables-save') do |r|
            expect(r.stdout).to match(%r{-A INPUT -i enp0s8 -p icmp -m condition ! --condition "isblue"  -m comment --comment "010 isblue ipv4" -j DROP})
          end
        end
      end
    end
  end
end
