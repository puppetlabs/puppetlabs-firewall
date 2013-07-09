require 'spec_helper_system'

describe "param based tests:" do
  # Takes a hash and converts it into a firewall resource
  def pp(params)
    name = params.delete('name') || '100 test'
    pm = <<-EOS
firewall { '#{name}':
    EOS

    params.each do |k,v| 
      pm += <<-EOS
  #{k} => #{v},
      EOS
    end

    pm += <<-EOS
}
    EOS
    pm
  end

  it 'test various params' do
    iptables_flush_all_tables

    facts = node.facts

    unless (facts['operatingsystem'] == 'CentOS') && \
      facts['operatingsystemrelease'] =~ /^5\./ then

      ppm = pp({
        'table' => "'raw'",
        'socket' => 'true',
        'chain' => "'PREROUTING'",
        'jump' => 'LOG',
        'log_level' => 'debug',
      })

      puppet_apply(ppm) do |r|
        r.exit_code.should == 2
        r.stderr.should be_empty
        r.refresh
        r.stderr.should be_empty
        r.exit_code.should be_zero
      end
    end
  end

  it 'test log rule' do
    iptables_flush_all_tables

    ppm = pp({
      'name' => '998 log all',
      'proto' => 'all',
      'jump' => 'LOG',
      'log_level' => 'debug',
    })
    puppet_apply(ppm) do |r|
      r.exit_code.should == 2
      r.stderr.should be_empty
      r.refresh
      r.stderr.should be_empty
      r.exit_code.should be_zero
    end
  end

  it 'test log rule - changing names' do
    iptables_flush_all_tables

    ppm1 = pp({
      'name' => '004 log all INVALID packets',
      'chain' => 'INPUT',
      'proto' => 'all',
      'state' => 'INVALID',
      'jump' => 'LOG',
      'log_level' => '3',
      'log_prefix' => '"IPTABLES dropped invalid: "',
    })

    ppm2 = pp({
      'name' => '003 log all INVALID packets',
      'chain' => 'INPUT',
      'proto' => 'all',
      'state' => 'INVALID',
      'jump' => 'LOG',
      'log_level' => '3',
      'log_prefix' => '"IPTABLES dropped invalid: "',
    })

    puppet_apply(ppm1) do |r|
      r.stderr.should be_empty
      r.exit_code.should == 2
    end

    ppm = <<-EOS + "\n" + ppm2
      resources { 'firewall':
        purge => true,
      }
    EOS
    puppet_apply(ppm) do |r|
      r.stderr.should be_empty
      r.exit_code.should == 2
    end
  end

  it 'test log rule - idempotent' do
    iptables_flush_all_tables

    ppm1 = pp({
      'name' => '004 log all INVALID packets',
      'chain' => 'INPUT',
      'proto' => 'all',
      'state' => 'INVALID',
      'jump' => 'LOG',
      'log_level' => '3',
      'log_prefix' => '"IPTABLES dropped invalid: "',
    })

    puppet_apply(ppm1) do |r|
      r.exit_code.should == 2
      r.stderr.should be_empty
      r.refresh
      r.stderr.should be_empty
      r.exit_code.should be_zero
    end
  end

  it 'test src_range rule' do
    iptables_flush_all_tables

    ppm = pp({
      'name'      => '997 block src ip range',
      'chain'     => 'INPUT',
      'proto'     => 'all',
      'action'    => 'drop',
      'src_range' => '"10.0.0.1-10.0.0.10"',
    })
    puppet_apply(ppm) do |r|
      r.exit_code.should == 2
      r.stderr.should be_empty
      r.refresh
      r.stderr.should be_empty
      r.exit_code.should be_zero
    end
  end

  it 'test dst_range rule' do
    iptables_flush_all_tables

    ppm = pp({
      'name'      => '998 block dst ip range',
      'chain'     => 'INPUT',
      'proto'     => 'all',
      'action'    => 'drop',
      'dst_range' => '"10.0.0.2-10.0.0.20"',
    })
    puppet_apply(ppm) do |r|
      r.exit_code.should == 2
      r.stderr.should be_empty
      r.refresh
      r.stderr.should be_empty
      r.exit_code.should be_zero
    end
  end

end
