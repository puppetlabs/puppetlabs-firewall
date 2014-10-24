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
  $ensure = running,
  $enable = true
) {

  # RHEL 7 and later and Fedora 15 and later require the iptables-services
  # package, which provides the /usr/libexec/iptables/iptables.init used by
  # lib/puppet/util/firewall.rb.
  if   ($::operatingsystem != 'Fedora' and versioncmp($::operatingsystemrelease, '7.0') >= 0)
    or ($::operatingsystem == 'Fedora' and versioncmp($::operatingsystemrelease, '15') >= 0) {
    service { "firewalld":
      ensure => stopped,
      enable => false,
      before => Package['iptables-services']
    }

    package { 'iptables-services':
      ensure  => present,
      before  => Service['iptables'],
    }
  }

  service { 'iptables':
    ensure    => $ensure,
    enable    => $enable,
    hasstatus => true,
    require   => File['/etc/sysconfig/iptables'],
  }

  file { '/etc/sysconfig/iptables':
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
  }
}
