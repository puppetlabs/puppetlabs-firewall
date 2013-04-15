# This helper file is specific to the system tests for puppetlabs-firewall
# and should be included by all tests under spec/system
require 'rspec-system/spec_helper'
require 'rspec-system-puppet/helpers'

# Just some helpers specific to this module
module LocalHelpers
   # This helper flushes all tables on the default machine.
   #
   # It checks that the flush command returns with no errors.
   #
   # @return [void]
   # @todo Need to optionally do the newer tables
   # @example
   #   it 'should flush tables' do
   #     iptables_flush_all_tables
   #   end
   def iptables_flush_all_tables
     ['filter', 'nat', 'mangle', 'raw'].each do |t|
       system_run("/sbin/iptables -t #{t} -F") do |r|
         r[:exit_code].should == 0
         r[:stderr].should == ''
       end
     end
   end
end

RSpec.configure do |c|
  # Project root for the firewall code
  proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))

  # Enable colour in Jenkins
  c.tty = true

  # Import in our local helpers
  c.include ::LocalHelpers

  # This is where we 'setup' the nodes before running our tests
  c.system_setup_block = proc do
    # TODO: find a better way of importing this into this namespace
    include RSpecSystemPuppet::Helpers

    # Install puppet
    puppet_install

    # Copy this module into the module path of the test node
    puppet_module_install(:source => proj_root, :module_name => 'firewall')
  end
end
