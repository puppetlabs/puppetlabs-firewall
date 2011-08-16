firewall { '000 allow foo':
  dport    => [7061, 7062],
  jump     => 'ACCEPT',
  proto    => 'tcp',
  provider => 'ip6tables'
}

firewall { '001 allow boo':
  jump        => 'ACCEPT',
  iniface     => 'eth0',
  sport       => 123,
  dport       => 123,
  proto       => 'tcp',
  destination => '::1/128',
  provider    => 'ip6tables'
}

firewall { '002 foo':
  dport    => 1233,
  proto    => 'tcp',
  jump     => 'DROP',
  provider => 'ip6tables'
}

firewall { '005 INPUT disregard DHCP':
  dport    => ['bootpc', 'bootps'],
  jump     => 'DROP',
  proto    => 'udp',
  provider => 'ip6tables'
}

firewall { '006 INPUT disregard netbios':
  dport    => ['netbios-ns', 'netbios-dgm', 'netbios-ssn'],
  jump     => 'DROP',
  proto    => 'udp',
  provider => 'ip6tables'
}

firewall { '006 Disregard CIFS':
  dport    => 'microsoft-ds',
  jump     => 'DROP',
  proto    => 'tcp',
  provider => 'ip6tables'
}

firewall { '010 icmp':
  proto    => 'ipv6-icmp',
  icmp     => 'echo-reply',
  jump     => 'ACCEPT',
  provider => 'ip6tables'
}

firewall { '010 INPUT allow loopback':
  iniface  => 'lo',
  chain    => 'INPUT',
  jump     => 'ACCEPT',
  provider => 'ip6tables'
}

firewall { '050 INPUT drop invalid':
  state    => 'INVALID',
  jump     => 'DROP',
  provider => 'ip6tables'
}

firewall { '051 INPUT allow related and established':
  state    => ['RELATED', 'ESTABLISHED'],
  jump     => 'ACCEPT',
  provider => 'ip6tables'
}

firewall { '053 INPUT allow ICMP':
  icmp     => '8',
  proto    => 'ipv6-icmp',
  jump     => 'ACCEPT',
  provider => 'ip6tables'
}

firewall { '055 INPUT allow DNS':
  sport    => 'domain',
  proto    => 'udp',
  jump     => 'ACCEPT',
  provider => 'ip6tables'
}

firewall { '999 FORWARD drop':
  chain    => 'FORWARD',
  jump     => 'DROP',
  provider => 'ip6tables'
}

firewall { '001 OUTPUT allow loopback':
  chain    => 'OUTPUT',
  outiface => 'lo',
  jump     => 'ACCEPT',
  provider => 'ip6tables'
}

firewall { '100 OUTPUT drop invalid':
  chain    => 'OUTPUT',
  state    => 'INVALID',
  jump     => 'DROP',
  provider => 'ip6tables'
}
