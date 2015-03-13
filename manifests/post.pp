# This creates all of the reject rules
class firewall::post {

  Firewall {
    require => Class['firewall::custom_firewall'],
  }

# default firewall rules

  firewall { '999 reject everything':
    proto  => 'all',
    action => 'reject',
    before => undef,
  }

  firewall { '998 reject everything':
    proto  => 'all',
    action => 'reject',
    chain  => 'FORWARD',
    before => undef,
  }
}
