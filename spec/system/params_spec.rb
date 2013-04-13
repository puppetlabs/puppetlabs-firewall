require 'spec_helper_system'

describe "param based tests:" do
  def pp(params)
    pm = <<-EOS
firewall { '100 test':
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

  [
    {
      'table' => "'raw'",
      'socket' => 'true',
      'chain' => "'PREROUTING'",
    },
  ].each do |param|
    it 'test param' do
      iptables_flush_all_tables

      ppm = pp(param)
      puppet_apply(ppm) do |r|
        r[:stderr].should == ''
        r[:exit_code].should == 2
      end

      # check idempotency
      puppet_apply(ppm) do |r|
        r[:stderr].should == ''
        r[:exit_code].should == 0
      end
    end
  end

end
