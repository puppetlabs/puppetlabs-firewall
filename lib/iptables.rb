# This class encodes and decodes iptables style -save and -restore formats
#
# @version 0.0.1
class Iptables

  VERSION = '0.0.1'

  # Takes the output for iptables-save returning a hash
  #
  # @example Decode iptables-save output
  #   Iptables.decode(`iptables-save`)
  # @param text [String] the raw output of iptables-save
  # @param opts [Hash] options for the decoder
  # @option opts [Bool] :debug If true, turns on debugging output
  # @option opts [String] :iptables_compatibilty version of iptables to be
  #   compatible with. Since some versions differ wildly, this might be
  #   necessary.
  # @return [Hash] returns a hash containing the parsed rules
  # @see Iptables::Decoder
  def self.decode(text, opts = {})
    decoder = Decoder.new(opts)
    decoder.decode(text)
  end

  # This is the internal Decoder class used by methods in the main class.
  class Decoder
    # @!attribute r opts
    #   @return [Hash] Options hash set on initialization
    attr_reader :opts

    # Initialize the decoder object
    #
    # @param opts [Hash] a hash of options
    # @option opts [Bool] :debug If true, turns on debugging output
    # @option opts [String] :iptables_compatibilty version of iptables to be
    #   compatible with. Since some versions differ wildly, this might be
    #   necessary.
    def initialize(opts = {})
      @opts = {
        :debug => false,
        :iptables_compatibility => nil,
      }.merge(opts)
    end

    # Decodes iptables-save input into a normalized hash
    #
    # @param text [String] the raw output of iptables-save
    # @return [Hash] returns a hash containing the parsed rules
    # @raise [Iptables::IptablesException] raised on a known exception
    def decode(text)
      {
        :metadata => {
          :ruby_iptables_version => VERSION,
          :iptables_compatibility => opts[:iptables_compatibility],
        },
        :result => parse_iptables_save(text),
      }
    end

    # Takes raw iptables-save input, returns a data hash
    #
    # @api private
    # @param text [String] the raw output of iptables-save
    # @return [Hash] returns a hash containing the parsed rules
    # @raise [Iptables::NoTable] raised if a rule is passed without a prior
    #   table declaration
    def parse_iptables_save(text)
      # Set the table to nil to begin with so we can detect append lines with no
      # prior table decleration.
      table = nil

      # Input line number for debugging later
      original_line_number = 0

      # Hash for storing the final result
      hash = {}

      text.each_line do |line|

        # If we find a table declaration, change table
        if line =~ /^\*([a-z]+)$/
          table = $1
          debug("Found table [#{table}] on line [#{original_line_number}]")
        end

        # If we find an append line, parse it
        if line =~ /^-A (\S+)/
          raise NoTable, "Found an append line [#{line}] on line [#{input_line}], but no table yet" if table.nil?

          chain = $1
          line_hash = parse_append_line(line)

          line_hash[:source] = {
            :original_line => line,
            :original_line_number => original_line_number,
          }

          hash[table] ||= {}
          hash[table][chain] ||= {}
          hash[table][chain][:rules] ||= []
          hash[table][chain][:rules] << line_hash
        end

        original_line_number += 1
      end

      hash
    end

    # Parses an append line return a hash
    #
    # @api private
    # @param text [String] a single iptables-save append line
    # @return [Hash] a hash containing data for the parsed rule
    def parse_append_line(line)
      ss = shellsplit(line)
      sh = switch_hash(ss)
      rh = rule(sh)
      {
        :shell_split => ss,
        :swtch_hash => sh,
        :rule => rh,
      }
    end

    # Takes a switch_hash and returns the rule as a hash
    #
    # @api private
    # @param switch_hash [Hash] a semi-parsed hash of the rule append line
    # @return [Hash] a parsed rule in hash format
    def rule(switch_hash)
      h = {
        :chain => nil,
        :parameters => {},
        :target => nil,
        :matches => [],
        :target_options => {},
      }

      # States
      match = false
      match_current = {}
      target = false

      switch_hash.each do |sh|
        sw = sh[:switch]
        if sw == "A"
          h[:chain] = sh[:values].first
          next
        end

        # Outside of match and target, these letters are the basic parameters
        if !match and !target and ["p", "s", "d", "i", "o", "f"].include? sw
          h[:parameters]["#{sh[:negate]? '!' : ''}#{sw}"] = sh[:values]
          next
        end

        # If option is 'm' then we are in a match
        if sw == 'm'
          if match and !match_current.empty?
            # We were already in a match, stow it
            h[:matches] << match_current
            match_current = {}
          end

          # Clear the current match
          match_current = {}
          match_current[:name] = sh[:values].first

          # Reset states
          match = true
          target = false

          next
        end

        # If option is 'j' then its a target, and anything else is a target_option
        if sw == "j"
          if match and !match_current.empty?
            # We were already in a match, stow it
            h[:matches] << match_current
            match_current = {}
          end

          h[:target] = sh[:values].first

          # Reset states
          target = true
          match = false

          next
        end

        if match
          match_current[:options] ||= {}
          match_current[:options]["#{sh[:negate]? '!' : ''}#{sw}"] = sh[:values]

          next
        end

        if target
          h[:target_options]["#{sh[:negate]? '!' : ''}#{sw}"] = sh[:values]
          next
        end
      end

      # Stow away any incomplete matches
      if match and !match_current.empty?
        h[:matches] << match_current
      end

      h
    end

    # Takes an argument array, and returns swtiches and values. It returns a hash
    # with switches on the LHS, and values on the right. Values appear as arrays.
    #
    # For switches without values, the RHS will just be the boolean `true`.
    #
    # @api private
    # @param split [Array] a list of arguments and values split in a shell-safe
    #   way
    # @return [Hash] a semi-parsed hash of arguments, values and negation status
    # @raise [Iptables::UnparseableSplit] raised when the split cannot be parsed
    #   into the correct format, usually because the input format is incorrect.
    def switch_hash(split)
      result = []

      current = nil

      debug("processing #{split.inspect}")

      split.each do |p|
        debug "p: #{p}"
        debug "pre current: #{current.inspect}" if current
        if p =~ /^--?(.+)/
          if current and !current.empty?
            if (current[:negate] and current[:switch]) or !current[:negate]
              result << current
              current = {}
            end
          else
            current = {}
          end
          current[:switch] = $1
        elsif p == '!'
          if current and !current.empty?
            unless current[:switch] \
              and iptables_backwards_negates.include? current[:switch]
              result << current
              current = {}
            end
          end
          current[:negate] = true
        else
          raise UnparseableSplit, "Found a value without corresponding arg" unless current
          current[:values] ||= []
          current[:values] << p
        end
        debug "post current: #{current.inspect}" if current
        debug "result: #{result.inspect}"
      end
      result << current

      result
    end

    # Break rule line into pices like a shell.
    #
    # The code itself is taken from Ruby core, and supplanted here to work with
    # older rubies.
    #
    # @api private
    # @param line [String] a list of shell arguments and values
    # @return [Array] an array of shell arguments and values split in a shell
    #   safe way.
    # @see http://svn.ruby-lang.org/repos/ruby/trunk/lib/shellwords.rb Original
    #   code
    # @raise [ArgumentError] raised on unmatched double quote
    def shellsplit(line)
      words = []
      field = ''
      line.scan(/\G\s*(?>([^\s\\\'\"]+)|'([^\']*)'|"((?:[^\"\\]|\\.)*)"|(\\.?)|(\S))(\s|\z)?/m) do
        |word, sq, dq, esc, garbage, sep|
        raise ArgumentError, "Unmatched double quote: #{line.inspect}" if garbage
        field << (word || sq || (dq || esc).gsub(/\\(.)/, '\\1'))
        if sep
          words << field
          field = ''
        end
      end
      words
    end

    def iptables_backwards_negates
      if opts[:iptables_compatibility] == '1.3.5'
        %w{p s d i o ctorigsrc ctorigdst ctreplsrc ctrepldst espspi length sports dports ports mss}
      else
        []
      end
    end

    # Prints debug output to STDOUT if debug switch is true
    #
    # @api private
    # @param text [String] text to output for debugging
    def debug(text)
      puts "D, #{text}" if @opts[:debug]
    end
  end

  # Base class for iptables parser exceptions
  class IptablesException < Exception
  end

  # Indicates a line was parsed but no prior table was declared
  class NoTable < IptablesException
  end

  # Raised if the line cannot be parsed
  class UnparseableLine < IptablesException
  end

  # Raised if the split cannot be parsed
  class UnparseableSplit < IptablesException
  end
end
