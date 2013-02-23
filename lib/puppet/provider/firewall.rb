class Puppet::Provider::Firewall < Puppet::Provider

  # Prefetch our rule list. This is ran once every time before any other
  # action (besides initialization of each object).
  def self.prefetch(resources)
    debug("[prefetch(resources)]")
    instances.each do |prov|
      if resource = resources[prov.name] || resources[prov.name.downcase]
        resource.provider = prov
      end
    end
  end

  # Look up the current status. This allows us to conventiently look up
  # existing status with properties[:foo].
  def properties
    if @property_hash.empty?
      @property_hash = query || {:ensure => :absent}
      @property_hash[:ensure] = :absent if @property_hash.empty?
    end
    @property_hash.dup
  end

  # Pull the current state of the list from the full list.  We're
  # getting some double entendre here....
  def query
    self.class.instances.each do |instance|
      if instance.name == self.name or instance.name.downcase == self.name
        return instance.properties
      end
    end
    nil
  end

  %w(chain table action burst destination dport gid icmp iniface jump limit log_level log_prefix name outiface pkttype port proto reject source sport state todest toports tosource uid).each do |property|
    define_method "#{property}" do
      @property_hash[property.to_sym]
    end

    define_method "#{property}=" do |value|
      @property_hash[:needs_change] = true
    end
  end

  # Executed if method is missing. In this case we are going to catch
  # unqualified property methods for dynamic property setting and getting.
  def method_missing(meth, *args, &block)
    dynamic_methods = self.class.instance_variable_get('@resource_map').keys
    dynamic_methods << :chain
    dynamic_methods << :table
    dynamic_methods << :action

    if dynamic_methods.include?(meth.to_sym) then
      if @property_hash[meth.to_sym] then
        return @property_hash[meth.to_sym]
      else
        return nil
      end
    elsif dynamic_methods.include?(meth.to_s.chomp("=").to_sym) then
      debug("Args: #{args}")
      @property_hash[:needs_change] = true
      return true
    end

    debug("Dynamic methods: #{dynamic_methods.join(' ')}")
    debug("Method missing: #{meth}. Calling super.")

    super
  end
end
