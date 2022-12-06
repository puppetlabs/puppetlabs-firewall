# frozen_string_literal: true

Facter.add(:ip6tables_version) do
  confine kernel: :Linux
  confine { Facter::Core::Execution.which('ip6tables') }
  setcode do
    version = Facter::Core::Execution.execute('ip6tables --version', { on_fail: nil })
    version.match(%r{\d+\.\d+\.\d+}).to_s if version
  end
end
