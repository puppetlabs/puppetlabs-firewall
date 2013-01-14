source :rubygems

gem 'rake', '~> 10.0.3'

group :test do
  gem 'rspec', '~> 2.12.0'
  gem 'mocha', '~> 0.13.1', :require => 'mocha/api'
  gem 'puppetlabs_spec_helper', '~> 0.4.0',
    :require => 'puppetlabs_spec_helper/module_spec_helper'

  if puppetversion = ENV['BUILD_PUPPET_VER']
    gem 'puppet', puppetversion
  else
    gem 'puppet'
  end

  if facterversion = ENV['BUILD_FACTER_VER']
    gem 'facter', facterversion
  else
    gem 'facter'
  end
end
