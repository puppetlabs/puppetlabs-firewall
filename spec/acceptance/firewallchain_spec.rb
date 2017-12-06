require 'spec_helper_acceptance'

describe 'puppet resource firewallchain command' do
  before :all do
    iptables_flush_all_tables
    ip6tables_flush_all_tables
  end

  describe 'ensure' do
    context 'when present' do
      pp1 = <<-PUPPETCODE
          firewallchain { 'MY_CHAIN:filter:IPv4':
            ensure  => present,
          }
      PUPPETCODE
      it 'applies cleanly' do
        # Run it twice and test for idempotency
        apply_manifest(pp1, catch_failures: true)
        apply_manifest(pp1, catch_changes: do_catch_changes)
      end

      it 'finds the chain' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{MY_CHAIN})
        end
      end
    end

    context 'when absent' do
      pp2 = <<-PUPPETCODE
          firewallchain { 'MY_CHAIN:filter:IPv4':
            ensure  => absent,
          }
      PUPPETCODE
      it 'applies cleanly' do
        # Run it twice and test for idempotency
        apply_manifest(pp2, catch_failures: true)
        apply_manifest(pp2, catch_changes: do_catch_changes)
      end

      it 'fails to find the chain' do
        shell('iptables-save') do |r|
          expect(r.stdout).not_to match(%r{MY_CHAIN})
        end
      end
    end
  end

  # XXX purge => false is not yet implemented
  # context 'when adding a firewall rule to a chain:' do
  #    pp3 = <<-PUPPETCODE
  #      firewallchain { 'MY_CHAIN:filter:IPv4':
  #        ensure  => present,
  #      }
  #      firewall { '100 my rule':
  #        chain   => 'MY_CHAIN',
  #        action  => 'accept',
  #        proto   => 'tcp',
  #        dport   => 5000,
  #      }
  #    PUPPETCODE
  #  it 'applies cleanly' do
  #    # Run it twice and test for idempotency
  #    apply_manifest(pp3, :catch_failures => true)
  #    apply_manifest(pp3, :catch_changes => do_catch_changes)
  #  end
  # end

  # context 'when not purge firewallchain chains:' do
  #    pp4 = <<-PUPPETCODE
  #      firewallchain { 'MY_CHAIN:filter:IPv4':
  #        ensure  => present,
  #        purge   => false,
  #        before  => Resources['firewall'],
  #      }
  #      resources { 'firewall':
  #        purge => true,
  #      }
  #    PUPPETCODE
  #  it 'does not purge the rule' do
  #    # Run it twice and test for idempotency
  #    apply_manifest(pp4, :catch_failures => true) do |r|
  #      expect(r.stdout).to_not match(/removed/)
  #      expect(r.stderr).to eq('')
  #    end
  #    apply_manifest(pp4, :catch_changes => do_catch_changes)
  #  end

  #    pp5 = <<-PUPPETCODE
  #      firewall { '100 my rule':
  #        chain   => 'MY_CHAIN',
  #        action  => 'accept',
  #        proto   => 'tcp',
  #        dport   => 5000,
  #      }
  #    PUPPETCODE
  #  it 'still has the rule' do
  #    # Run it twice and test for idempotency
  #    apply_manifest(pp5, :catch_changes => do_catch_changes)
  #  end
  # end

  describe 'policy' do
    after :all do
      shell('iptables -t filter -P FORWARD ACCEPT')
    end

    context 'when DROP' do
      pp6 = <<-PUPPETCODE
          firewallchain { 'FORWARD:filter:IPv4':
            policy  => 'drop',
          }
      PUPPETCODE
      it 'applies cleanly' do
        # Run it twice and test for idempotency
        apply_manifest(pp6, catch_failures: true)
        apply_manifest(pp6, catch_changes: do_catch_changes)
      end

      it 'finds the chain' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{FORWARD DROP})
        end
      end
    end
  end
end
