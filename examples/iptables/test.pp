firewall { '000 allow foo':
  dport => [7061, 7062],
  jump => "ACCEPT",
  proto => "tcp",
}

firewall { '001 allow boo':
  jump => "ACCEPT",
  iniface => "eth0",
  sport => "123",
  dport => "123",
  proto => "tcp",
  destination => "1.1.1.0/24",
  source => "2.2.2.0/24",
}

firewall { '999 bar':
  dport => "1233",
  proto => "tcp",
  jump => "DROP",
}

firewall { '002 foo':
  dport => "1233",
  proto => "tcp",
  jump => "DROP",
}

firewall { '010 icmp':
  proto => "icmp",
  icmp => "echo-reply",
  jump => "ACCEPT",
}

firewall { '010 INPUT allow loopback':
  iniface => 'lo',
  chain => 'INPUT',
  jump => 'ACCEPT'
}

firewall { '005 INPUT disregard DHCP':
  dport => ['bootpc', 'bootps'],
  jump => 'DROP',
  proto => 'udp'
}

firewall { '006 INPUT disregard netbios':
  proto => 'udp',
  dport => ['netbios-ns', 'netbios-dgm', 'netbios-ssn'],
  jump => 'DROP'
}

firewall { '006 Disregard CIFS':
  dport => 'microsoft-ds',
  jump => 'DROP',
  proto => 'tcp'
}

firewall { '050 INPUT drop invalid':
  state => 'INVALID',
  jump => 'DROP'
}

firewall { '051 INPUT allow related and established':
  state => ['RELATED', 'ESTABLISHED'],
  jump => 'ACCEPT'
}

firewall { '053 INPUT allow ICMP':
  icmp => '8',
  proto => 'icmp',
  jump => 'ACCEPT'
}

firewall { '055 INPUT allow DNS':
  proto => 'udp',
  jump => 'ACCEPT',
  sport => 'domain'
}

firewall { '999 FORWARD drop':
  chain => 'FORWARD',
  jump => 'DROP'
}

firewall { '001 OUTPUT allow loopback':
  chain => 'OUTPUT',
  outiface => 'lo',
  jump => 'ACCEPT'
}

firewall { '100 OUTPUT drop invalid':
  chain => 'OUTPUT',
  state => 'INVALID',
  jump => 'DROP'
}

resources { 'firewall':
  purge => true
}
