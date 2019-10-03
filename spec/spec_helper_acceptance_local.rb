def iptables_flush_all_tables
  ['filter', 'nat', 'mangle', 'raw'].each do |t|
    expect(run_shell("iptables -t #{t} -F").stderr).to eq('')
  end
end

def ip6tables_flush_all_tables
  ['filter', 'mangle'].each do |t|
    expect(run_shell("ip6tables -t #{t} -F").stderr).to eq('')
  end
end

def install_iptables
  run_shell('iptables -V')
rescue
  run_shell('apt-get install iptables -y')
end

def iptables_version
  install_iptables
  x = run_shell('iptables -V')
  x.stdout.split(' ')[1][1..-1]
end

def pre_setup
  run_shell('mkdir -p /lib/modules/`uname -r`')
  run_shell('depmod -a')
end

def update_profile_file
  run_shell("sed -i '/mesg n/c\\test -t 0 && mesg n || true' ~/.profile")
  run_shell("sed -i '/mesg n || true/c\\test -t 0 && mesg n || true' ~/.profile")
end
