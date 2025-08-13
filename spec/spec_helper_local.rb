# frozen_string_literal: true

if ENV['COVERAGE'] == 'yes'
  require 'simplecov'
  require 'simplecov-console'
  require 'codecov'

  SimpleCov.formatters = [
    SimpleCov::Formatter::HTMLFormatter,
    SimpleCov::Formatter::Console,
    SimpleCov::Formatter::Codecov,
  ]
  SimpleCov.start do
    track_files 'lib/**/*.rb'

    add_filter '/spec'

    # do not track vendored files
    add_filter '/vendor'
    add_filter '/.vendor'

    # do not track gitignored files
    # this adds about 4 seconds to the coverage check
    # this could definitely be optimized
    add_filter do |f|
      # system returns true if exit status is 0, which with git-check-ignore means file is ignored
      system("git check-ignore --quiet #{f.filename}")
    end
  end
end

shared_context 'when ArchLinux' do
  let :facts do
    {
      kernel: 'Linux',
      os: {
        name: 'ArchLinux',
        family: 'ArchLinux'
      },
      identity: {
        uid: 'root'
      }
    }
  end
end

shared_context 'when Debian 11' do
  let(:facts) { on_supported_os['debian-11-x86_64'] }
end

shared_context 'when Debian 12' do
  let(:facts) { on_supported_os['debian-12-x86_64'] }
end

shared_context 'when Debian Unstable' do
  let(:facts) do
    {
      kernel: 'Linux',
      os: {
        family: 'Debian',
        name: 'Debian',
        release: { full: 'unstable' }
      },
      identity: {
        uid: 'root'
      }
    }
  end
end

shared_context 'when Ubuntu 18.04' do
  let(:facts) { on_supported_os['ubuntu-18.04-x86_64'] }
end

shared_context 'when RedHat 7' do
  let(:facts) { on_supported_os['redhat-7-x86_64'] }
end

shared_context 'when RedHat 8' do
  let(:facts) { on_supported_os['redhat-8-x86_64'] }
end
