require 'rubygems'
require 'bundler/setup'

Bundler.require :default

require 'rspec/core/rake_task'
require 'puppetlabs_spec_helper/rake_tasks'
require 'rspec-system/rake_task'

require 'puppet-lint/tasks/puppet-lint'
PuppetLint.configuration.ignore_paths = ['vendor/**/*.pp']

task :default do
  sh %{rake -T}
end

desc 'Run reasonably quick tests for CI'
task :ci => [
  :lint,
  :spec,
]
