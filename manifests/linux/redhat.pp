# = Class: firewall::linux::redhat
#
# Manages the `iptables` service on RedHat-alike systems.
#
# == Parameters:
#
# [*ensure*]
#   Ensure parameter passed onto Service[] resources.
#   Default: running
#
# [*enable*]
#   Enable parameter passed onto Service[] resources.
#   Default: true
#
class firewall::linux::redhat (
  $ensure       = running,
  $enable       = true,
  $service_name = $::firewall::params::service_name,
  $package_name = $::firewall::params::package_name,
) inherits ::firewall::params {

  # RHEL 7 and later and Fedora 15 and later require the iptables-services
  # package, which provides the /usr/libexec/iptables/iptables.init used by
  # lib/puppet/util/firewall.rb.
  if ($::operatingsystem != 'Amazon')
  and (($::operatingsystem != 'Fedora' and versioncmp($::operatingsystemrelease, '7.0') >= 0)
  or  ($::operatingsystem == 'Fedora' and versioncmp($::operatingsystemrelease, '15') >= 0)) {
    service { 'firewalld':
      ensure => stopped,
      enable => false,
      before => Package[$package_name],
    }
  }

  if $package_name {
    package { $package_name:
      ensure => present,
      before => Service[$service_name],
    }
  }

  service { $service_name:
    ensure    => $ensure,
    enable    => $enable,
    hasstatus => true,
    require   => File['/etc/sysconfig/iptables'],
  }

  file { '/etc/sysconfig/iptables':
    ensure => present,
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
  }

  file { '/etc/sysconfig/iptables-config':
    ensure => present,
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
    source => 'puppet:///modules/puppetlabs-firewall/iptables-config',
  }
}
