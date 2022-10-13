# frozen_string_literal: true

Facter.add(:ip6tables_version) do
  confine kernel: :Linux
  setcode do
    version = Facter::Core::Execution.execute('ip6tables --version')
    if version
      version.match(%r{\d+\.\d+\.\d+}).to_s
    else
      nil
    end
  end
end
