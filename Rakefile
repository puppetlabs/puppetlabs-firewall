require 'rake'
require 'rspec/core/rake_task'

task :default => [:test]

desc 'Run RSpec'
RSpec::Core::RakeTask.new(:test)

desc 'Generate code coverage'
RSpec::Core::RakeTask.new(:coverage) do |t|
  t.rcov = true
  t.rcov_opts = ['--exclude', 'spec']
end
