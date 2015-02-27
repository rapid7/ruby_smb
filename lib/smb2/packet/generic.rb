# A basic Protocol Data Unit (PDU) for the SMB2 protocol.
#
# All other classes in the {Smb2::Packet} namespace inherit from this class.

# [[MS-SMB2] 2.2 Message Syntax](https://msdn.microsoft.com/en-us/library/cc246497.aspx)
class Smb2::Packet::Generic < BitStruct
  default_options endian: 'little'

  # List of all {.data_buffer} field names
  # @return [Array<String>]
  def self.data_buffer_fields
    @data_buffer_fields ||= []
  end

  # Define a data buffer consisting of an offset, 16- or 32-bit length, and a
  # value of `length` bytes at the end of the packet. Will create attributes
  # for the thing itself as well as one for `<name>_length` and
  # `<name>_offset`
  #
  # @param name [Symbol]
  # @param bit_length [Fixnum] length in bits of the buffer's `length` field.
  # @option opts [Fixnum] :padding (0) number of bits to align after the length,
  # @option opts [Fixnum] :offset_bitlength (16) length in bits of the
  #   buffer's `offset` field.
  # @return [void]
  def self.data_buffer(name, bit_length=16, opts={})
    (@data_buffer_fields ||= []) << name

    self.unsigned "#{name}_offset", (opts[:offset_bitlength] || 16), endian: 'little'
    self.unsigned "#{name}_padding", opts[:padding] if opts.has_key?(:padding)
    self.unsigned "#{name}_length", bit_length, endian: 'little'

    class_eval do

      define_method(name) do
        field_offset = self.send("#{name}_offset")
        field_length = self.send("#{name}_length")
        # Must use #to_s so we get the whole packet packed because offset is from
        # beginning of header.
        to_s.slice(field_offset, field_length)
      end

      define_method("#{name}=") do |other|
        @data_buffers[name] = other
        recalculate
      end

    end

    self
  end

  # @see BitStruct#initialize
  def initialize(*args)
    @data_buffers = {}
    super do
      if !self.class.data_buffer_fields.empty?
        self.class.data_buffer_fields.each do |buffer_name|
          @data_buffers[buffer_name] = self.send(buffer_name) || ""
        end
        recalculate
      end
      yield self if block_given?
    end
  end

  # A generic flag checking method. Subclasses should have a field named
  # `flags`, and constants `FLAGS` and `FLAG_NAMES`.
  #
  # @param flag [Symbol] a key in `FLAGS`
  def has_flag?(flag)
    raise Smb2::Packet::InvalidFlagError, flag.to_s unless self.class::FLAG_NAMES.include?(flag)
    (flags & self.class::FLAGS[flag]) == self.class::FLAGS[flag]
  end

  # Fix the length and offset fields for all {.data_buffer data buffer fields}
  #
  # @return [self]
  def recalculate
    offset = self.header.header_len + (struct_size & ~1)
    new_buffer = ""

    self.class.data_buffer_fields.each do |buffer_name|
      new_size = @data_buffers[buffer_name].size
      if new_size.zero?
        self.send("#{buffer_name}_offset=", 0)
      else
        new_buffer << @data_buffers[buffer_name]
        self.send("#{buffer_name}_length=", new_size)
        self.send("#{buffer_name}_offset=", offset)
      end
      offset += new_size
    end
    self.buffer = new_buffer

    self
  end

end
