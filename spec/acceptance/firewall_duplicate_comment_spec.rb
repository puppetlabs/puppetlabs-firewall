# frozen_string_literal: true

require 'spec_helper_acceptance'

def make_manifest(behaviour)
  pp = <<-PUPPETCODE
    class { 'firewall': }
    resources { 'firewall':
      purge => true,
    }

    firewall { '550 destination':
      proto  => tcp,
      dport   => '550',
      action => accept,
      destination => '192.168.2.0/24',
      onduplicaterulebehaviour => #{behaviour}
    }
    PUPPETCODE

  pp
end

describe 'firewall - duplicate comments' do
  before(:all) do
    if os[:family] == 'ubuntu' || os[:family] == 'debian'
      update_profile_file
    end
  end

  before(:each) do
    run_shell('iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 551 -j ACCEPT -m comment --comment "550 destination"')
  end

  after(:each) do
    iptables_flush_all_tables
  end

  context 'when onduplicateerrorhevent is set to error' do
    it 'raises an error' do
      run_shell('iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 551 -j ACCEPT -m comment --comment "550 destination"')
      pp = make_manifest('error')

      apply_manifest(pp) do |r|
        expect(r.stderr).to include('Error: /Stage[main]/Main/Firewall[550 destination]: Could not evaluate: Duplicate rule found for 550 destination. Skipping update.')
      end
    end
  end

  context 'when onduplicateerrorhevent is set to warn' do
    run_shell('iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 551 -j ACCEPT -m comment --comment "550 destination"')

    it 'warns and continues' do
      run_shell('iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 551 -j ACCEPT -m comment --comment "550 destination"')
      pp = make_manifest('warn')

      apply_manifest(pp) do |r|
        expect(r.stderr).to include('Warning: Firewall[550 destination](provider=iptables): Duplicate rule found for 550 destination.. This may add an additional rule to the system.')
      end
    end
  end

  context 'when onduplicateerrorhevent is set to ignore' do
    run_shell('iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 551 -j ACCEPT -m comment --comment "550 destination"')

    it 'continues silently' do
      run_shell('iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 551 -j ACCEPT -m comment --comment "550 destination"')
      pp = make_manifest('ignore')

      apply_manifest(pp) do |r|
        expect(r.stderr).to be_empty
      end
    end
  end
end
