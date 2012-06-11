dir = File.expand_path(File.dirname(__FILE__))
$LOAD_PATH.unshift File.join(dir, 'lib')

# Don't want puppet getting the command line arguments for rake or autotest
ARGV.clear

require 'puppet'
require 'mocha'
gem 'rspec', '>=2.0.0'
require 'rspec/expectations'

# So everyone else doesn't have to include this base constant.
module PuppetSpec
  FIXTURE_DIR = File.join(dir = File.expand_path(File.dirname(__FILE__)), "fixtures") unless defined?(FIXTURE_DIR)
end

require 'pathname'
require 'tmpdir'

require 'puppet_spec/verbose'
require 'puppet_spec/files'
require 'puppet_spec/fixtures'
require 'puppet_spec/matchers'
require 'monkey_patches/alias_should_to_must'
require 'monkey_patches/publicize_methods'

Pathname.glob("#{dir}/shared_behaviours/**/*.rb") do |behaviour|
  require behaviour.relative_path_from(Pathname.new(dir))
end

RSpec.configure do |config|
  include PuppetSpec::Fixtures

  config.mock_with :mocha

  config.before :each do
    GC.disable

    # these globals are set by Application
    $puppet_application_mode = nil
    $puppet_application_name = nil

    # REVISIT: I think this conceals other bad tests, but I don't have time to
    # fully diagnose those right now.  When you read this, please come tell me
    # I suck for letting this float. --daniel 2011-04-21
    Signal.stubs(:trap)

    # Set the confdir and vardir to gibberish so that tests
    # have to be correctly mocked.
    Puppet[:confdir] = "/dev/null"
    Puppet[:vardir] = "/dev/null"

    # Avoid opening ports to the outside world
    Puppet.settings[:bindaddress] = "127.0.0.1"

    @logs = []
    # This tests allows the spec_helper to be >2.6.7 and >2.7.1 compatible
    # as the Puppet::Test::LogCollector facility wasn't available until 2.7.x
    if Puppet.const_defined?("Test") and Puppet::Test.const_defined?("LogCollector")
      Puppet::Util::Log.newdestination(Puppet::Test::LogCollector.new(@logs))
    else
      Puppet::Util::Log.newdestination(@logs)
    end

    @log_level = Puppet::Util::Log.level
  end

  config.after :each do
    Puppet.settings.clear
    Puppet::Node::Environment.clear
    Puppet::Util::Storage.clear
    if Puppet::Util.const_defined?("ExecutionStub")
      Puppet::Util::ExecutionStub.reset
    end

    PuppetSpec::Files.cleanup

    @logs.clear
    Puppet::Util::Log.close_all
    Puppet::Util::Log.level = @log_level

    GC.enable
  end
end
