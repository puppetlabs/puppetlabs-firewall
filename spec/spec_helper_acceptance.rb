require 'beaker-rspec'
require 'beaker/puppet_install_helper'

def iptables_flush_all_tables
  ['filter', 'nat', 'mangle', 'raw'].each do |t|
    expect(shell("iptables -t #{t} -F").stderr).to eq("")
  end
end

def ip6tables_flush_all_tables
  ['filter'].each do |t|
    expect(shell("ip6tables -t #{t} -F").stderr).to eq("")
  end
end

run_puppet_install_helper

UNSUPPORTED_PLATFORMS = ['windows','Solaris','Darwin']

RSpec.configure do |c|
  # Project root
  proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))

  # Readable test descriptions
  c.formatter = :documentation

  # Configure all nodes in nodeset
  c.before :suite do
    # Install module and dependencies
    hosts.each do |host|
      copy_module_to(host, :source => proj_root, :module_name => 'firewall')
      on host, puppet('module install puppetlabs-stdlib --version 3.2.0'), { :acceptable_exit_codes => [0,1] }
    end
  end
end
