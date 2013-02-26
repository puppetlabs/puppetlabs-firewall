Facter.add(:iptables_persistent_version) do
  confine :operatingsystem => %w{Debian Ubuntu}
  setcode do
    cmd = "dpkg-query -Wf '${Version}' iptables-persistent"
    version = Facter::Util::Resolution.exec(cmd)

    if version.nil? or !version.match(/\d+\.\d+/)
      nil
    else
      version
    end
  end
end
