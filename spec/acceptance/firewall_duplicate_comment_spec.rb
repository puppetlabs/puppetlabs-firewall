# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'firewall - duplicate comments' do
  before(:all) do
    if os[:family] == 'ubuntu' || os[:family] == 'debian'
      update_profile_file
    end
  end

  after(:each) do
    iptables_flush_all_tables
  end

  context 'when a duplicate comment is found' do
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
    }
    PUPPETCODE

    it 'raises an error' do
      run_shell('iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 551 -j ACCEPT -m comment --comment "550 destination"')
      run_shell('iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 552 -j ACCEPT -m comment --comment "550 destination"')

      apply_manifest(pp) do |r|
        expect(r.stderr).to include('Duplicate rule found for 550 destination. Skipping update.')
      end
    end
  end
end
