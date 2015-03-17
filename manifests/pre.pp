# This creates all of the default rules
class firewall::pre {

  require firewall::service

  Firewall {
    before => Class['firewall::post'],
  }

# default firewall rules

  firewall { '000 accept all icmp':
    proto  => 'icmp',
    action => 'accept',
  }

  firewall { '001 accept all to lo interface':
    proto   => 'all',
    action  => 'accept',
    iniface => 'lo',
  }

  firewall { '002 accept related established rules':
    proto  => 'all',
    state  => ['RELATED', 'ESTABLISHED'],
    action => 'accept',
  }

  firewall { '003 accept new ssh':
    proto  => 'tcp',
    state  => ['NEW'],
    dport  => '22',
    action => 'accept',
  }
}
