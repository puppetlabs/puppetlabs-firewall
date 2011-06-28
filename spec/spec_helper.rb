require 'rspec'
require 'puppet'
$LOAD_PATH.unshift('../../lib', __FILE__)

RSpec.configure do |config|
  def setup_provider(type, prov)
    @provider = Puppet::Type.type(type).provider(prov)
  end

  def setup_resource(type, options={})
    @resource = Puppet::Type.type(type).new(options)
  end

  def setup_instance(prov, type)
    @instance = prov.new(type)
  end
end
