# @summary
#   Manages the `iptables` service on RedHat-alike systems.
#
# @param ensure
#   Ensure parameter passed onto Service[] resources. Valid options: 'running' or 'stopped'. Defaults to 'running'.
#
# @param ensure_v6
#   Ensure parameter passed onto Service[] resources. Valid options: 'running' or 'stopped'. Defaults to 'undef'.
#
# @param enable
#   Enable parameter passed onto Service[] resources. Defaults to 'true'.
#
# @param enable_v6
#   Enable parameter passed onto Service[] resources. Defaults to 'undef'.
#
# @param service_name
#   Specify the name of the IPv4 iptables service. Defaults defined in firewall::params.
#
# @param service_name_v6
#   Specify the name of the IPv4 iptables service. Defaults defined in firewall::params.
#
# @param package_name
#   Specify the platform-specific package(s) to install. Defaults defined in firewall::params.
#
# @param package_ensure
#   Controls the state of the iptables package on your system. Valid options: 'present' or 'latest'. Defaults to 'latest'.
#
# @param sysconfig_manage
#   Enable sysconfig configuration for iptables/ip6tables files. Defaults defined in firewall::params. This is disabled for RedHat/CentOS 8+.
#
# @api private
#
class firewall::linux::redhat (
  $ensure           = running,
  $ensure_v6        = undef,
  $enable           = true,
  $enable_v6        = undef,
  $service_name     = $::firewall::params::service_name,
  $service_name_v6  = $::firewall::params::service_name_v6,
  $package_name     = $::firewall::params::package_name,
  $package_ensure   = $::firewall::params::package_ensure,
  $sysconfig_manage = $::firewall::params::sysconfig_manage,
) inherits ::firewall::params {
  $_ensure_v6 = pick($ensure_v6, $ensure)
  $_enable_v6 = pick($enable_v6, $enable)

  # RHEL 7 / CentOS 7 and later and Fedora 15 and later require the iptables-services
  # package, which provides the /usr/libexec/iptables/iptables.init used by
  # lib/puppet/util/firewall.rb.
  if ($::operatingsystem != 'Amazon')
    and (($::operatingsystem != 'Fedora' and versioncmp($::operatingsystemrelease, '7.0') >= 0)
    or  ($::operatingsystem == 'Fedora' and versioncmp($::operatingsystemrelease, '15') >= 0)) {
    service { 'firewalld':
      ensure => stopped,
      enable => false,
      before => [Package[$package_name], Service[$service_name]],
    }
  }

  # in RHEL 8 / CentOS 8 nftables provides a replacement iptables cli
  # but there is no nftables specific for ipv6 so throw a warning
  if !$service_name_v6 and ($ensure_v6 or $enable_v6) {
    warning('No v6 service available, $ensure_v6 and $enable_v6 are ignored')
  }

  if $package_name {
    ensure_packages($package_name, {
        'ensure' => $package_ensure,
        'before' => Service[$service_name]}
    )
  }

  if ($::operatingsystem != 'Amazon')
    and (($::operatingsystem != 'Fedora' and versioncmp($::operatingsystemrelease, '7.0') >= 0)
    or  ($::operatingsystem == 'Fedora' and versioncmp($::operatingsystemrelease, '15') >= 0)) {
    if $ensure == 'running' {
      exec { '/usr/bin/systemctl daemon-reload':
        require     => Package[$package_name],
        before      => Service[$service_name, $service_name_v6],
        subscribe   => Package[$package_name],
        refreshonly => true,
      }
    }
  }

  if ($::operatingsystem == 'Amazon') and (versioncmp($::operatingsystemmajrelease, '4') >= 0)
    or ($::operatingsystem == 'Amazon') and (versioncmp($::operatingsystemmajrelease, '2') >= 0) {
    service { $service_name:
      ensure    => $ensure,
      enable    => $enable,
      hasstatus => true,
      provider  => systemd,
    }
    if $service_name_v6 {
      service { $service_name_v6:
        ensure    => $_ensure_v6,
        enable    => $_enable_v6,
        hasstatus => true,
        provider  => systemd,
      }
    }
  } else {
    service { $service_name:
      ensure    => $ensure,
      enable    => $enable,
      hasstatus => true,
    }
    if $service_name_v6 {
      service { $service_name_v6:
        ensure    => $_ensure_v6,
        enable    => $_enable_v6,
        hasstatus => true,
      }
    }
  }

  if $sysconfig_manage {
    file { "/etc/sysconfig/${service_name}":
      ensure => present,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }
    if $service_name_v6 {
      file { "/etc/sysconfig/${service_name_v6}":
        ensure => present,
        owner  => 'root',
        group  => 'root',
        mode   => '0600',
      }
    }

    # Before puppet 4, the autobefore on the firewall type does not work - therefore
    # we need to keep this workaround here
    if versioncmp($::puppetversion, '4.0') <= 0 {
      File<| title == "/etc/sysconfig/${service_name}" |> -> Service<| title == $service_name |>
      File<| title == "/etc/sysconfig/${service_name_v6}" |> -> Service<| title == $service_name_v6 |>
    }

    # Redhat 7 selinux user context for /etc/sysconfig/iptables is set to system_u
    # Redhat 7 selinux type context for /etc/sysconfig/iptables is set to system_conf_t
    case $::selinux {
      #lint:ignore:quoted_booleans
      'true',true: {
        case $::operatingsystem {
          'CentOS': {
            case $::operatingsystemrelease {
              /^5\..*/: {
                $seluser = 'system_u'
                $seltype = 'etc_t'
              }

              /^6\..*/: {
                $seluser = 'unconfined_u'
                $seltype = 'system_conf_t'
              }

              /^7\..*/: {
                $seluser = 'system_u'
                $seltype = 'system_conf_t'
              }

              default : {
                $seluser = 'unconfined_u'
                $seltype = 'etc_t'
              }
            }
            File<| title == "/etc/sysconfig/${service_name}" |> { seluser => $seluser, seltype => $seltype }
            File<| title == "/etc/sysconfig/${service_name_v6}" |> { seluser => $seluser, seltype => $seltype }
          }

          # Fedora uses the same SELinux context as Redhat
          'Fedora': {
            $seluser = 'system_u'
            $seltype = 'system_conf_t'
            File<| title == "/etc/sysconfig/${service_name}" |> { seluser => $seluser, seltype => $seltype }
            File<| title == "/etc/sysconfig/${service_name_v6}" |> { seluser => $seluser, seltype => $seltype }
          }

          default: {}

        }
      }
      default: {}
      #lint:endignore
    }
  }
}
