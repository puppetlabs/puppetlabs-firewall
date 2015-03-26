require 'spec_helper_acceptance'

describe 'firewall on RHEL7', :unless => (UNSUPPORTED_PLATFORMS.include?(fact('osfamily')) || !is_rhel7( !is_rhel7( fact('osfamily'), fact('operatingsystem'), fact('operatingsystemrelease') ) ) do
  before :all do
    iptables_flush_all_tables
  end

  it 'should run successfully' do
    pp = "
    class { 'firewall': 
      remove_firewalld => true,
    }
    ->
    resources { 'firewall':
      purge   => true,
    }
    ->
    firewall { '555 - test':
      proto  => tcp,
      port   => '555',
      action => accept,
    }
    "

    # Run it twice and test for idempotency
    apply_manifest(pp, :catch_failures => true, :debug => true)
    expect(apply_manifest(pp, :catch_failures => true, :debug => true).exit_code).to be_zero
  end

end
