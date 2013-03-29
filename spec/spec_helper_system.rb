# This helper file is specific to the system tests for puppetlabs-firewall
# and should be included by all tests under spec/system
require 'rspec-system/spec_helper'

RSpec.configure do |c|
  # Project root for the firewall code
  proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))

  # This is where we 'setup' the nodes before running our tests
  c.system_setup_block = proc do
    # TODO: find a better way of importing these into this namespace
    include RSpecSystem::Helpers
    include RSpecSystem::Log

    # TODO: this setup stuff is fairly generic, should move this into a plugin
    # for rspec-system.

    # Grab facts from node
    facts = system_node.facts

    # Remove annoying mesg n from profile, otherwise on Debian we get:
    # stdin: is not a tty which messes with our tests later on.
    if facts['osfamily'] == 'Debian'
      log.info("Remove 'mesg n' from profile to stop noise")
      system_run("sed -i 's/^mesg n/# mesg n/' /root/.profile")
    end

    # Grab PL repository and install PL copy of puppet
    log.info "Starting installation of puppet from PL repos"
    if facts['osfamily'] == 'RedHat'
      system_run('rpm -ivh http://yum.puppetlabs.com/el/5/products/i386/puppetlabs-release-5-6.noarch.rpm')
      system_run('yum install -y puppet')
    elsif facts['osfamily'] == 'Debian'
      system_run("wget http://apt.puppetlabs.com/puppetlabs-release-#{facts['lsbdistcodename']}.deb")
      system_run("dpkg -i puppetlabs-release-#{facts['lsbdistcodename']}.deb")
      system_run('apt-get update')
      system_run('apt-get install -y puppet')
    end

    # Prep modules dir
    log.info("Preparing modules dir")
    system_run('mkdir -p /etc/puppet/modules')

    # Copy the current code into appropriate module dir
    # TODO: we could always use the build process, copy tarball across etc.
    # just a shame the puppet module tool doesn't handle standalone tarballs
    # yet.
    log.info("Now transferring module onto node")
    system_rcp(:sp => proj_root, :dp => '/etc/puppet/modules/firewall')
  end
end
