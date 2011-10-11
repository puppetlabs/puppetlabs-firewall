require 'rake'
require 'rspec/core/rake_task'

task :default do
  sh %{rake -T}
end

# Aliases for spec. The (s) versions are used by rvm specs/tests.
task :test    => [:spec]
task :tests   => [:spec]
task :specs   => [:spec]

desc 'Run all RSpec tests'
RSpec::Core::RakeTask.new(:spec) do |t|
  t.rspec_opts = ['--color']
end

desc 'Generate code coverage'
RSpec::Core::RakeTask.new(:coverage) do |t|
  t.rcov = true
  t.rcov_opts = ['--exclude', 'spec']
end
