# @summary
#   Installs the `iptables-persistent` package for Debian-alike systems. This allows rules to be stored to file and restored on boot.
#
# @param ensure
#   Ensure parameter passed onto Service[] resources. Valid options: 'running' or 'stopped'. Defaults to 'running'.
#
# @param enable
#   Enable parameter passed onto Service[] resources. Defaults to 'true'.
#
# @param service_name
#   Specify the name of the IPv4 iptables service. Defaults defined in firewall::params.
#
# @param package_name
#   Specify the platform-specific package(s) to install. Defaults defined in firewall::params.
#
# @param package_ensure
#   Controls the state of the iptables package on your system. Valid options: 'present' or 'latest'. Defaults to 'latest'.
#
# @api private
#
class firewall::linux::debian (
  Enum[running, stopped, 'running', 'stopped']   $ensure         = running,
  Variant[Boolean, String[1]]                    $enable         = true,
  Variant[String[1], Array[String[1]]]           $service_name   = $firewall::params::service_name,
  Optional[Variant[String[1], Array[String[1]]]] $package_name   = $firewall::params::package_name,
  Enum[present, latest, 'present', 'latest']     $package_ensure = $firewall::params::package_ensure,
) inherits firewall::params {
  if $package_name {
    stdlib::ensure_packages([$package_name], {
        ensure  => $package_ensure
    })
  }

  # This isn't a real service/daemon. The start action loads rules, so just
  # needs to be called on system boot.
  service { $service_name:
    ensure    => $ensure,
    enable    => $enable,
    hasstatus => true,
    require   => Package[$package_name],
  }
}
