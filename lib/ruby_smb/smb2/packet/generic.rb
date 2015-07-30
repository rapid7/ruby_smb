module RubySMB::SMB2::Packet
  # Class that represents a generic SMB2 packet.
  class Generic < BitStruct

    # Values in SMB are always little endian. Make all fields default to little
    # endian so we don't have to do it in every call to `unsigned`, etc.
    default_options endian: 'little'

    string   :magic,         32, default: "\xfeSMB".force_encoding("binary")
    unsigned :header_len,    16, default: 64
    unsigned :credit_charge, 16, default: 1

    unsigned :nt_status,     32

    unsigned :command,       16

    unsigned :credits_requested, 16, default: 31
    unsigned :header_flags,  32
    unsigned :chain_offset,  32
    unsigned :command_seq,   64
    unsigned :process_id,    32, default: 0xfeff
    unsigned :tree_id,       32
    unsigned :session_id,    64

    # 16 bytes
    string :signature,       (8 * 16)

    def response?
      has_header_flag?(:RESPONSE)
    end

    ##
    # Class methods
    ##

    # List of all {.data_buffer} field names
    # @return [Array<String>]
    def self.data_buffer_fields
      @data_buffer_fields ||= []
    end

    # Define a data buffer consisting of an offset, 16- or 32-bit length, an
    # optional padding, and a value of `length` bytes at the end of the packet.
    # Will create attributes for the thing itself as well as one for
    # `<name>_length`, `<name>_offset`, and possibly `<name>_padding`.
    #
    # @param name [Symbol]
    # @param bit_length [Fixnum] length in bits of the buffer's `length` field.
    # @param padding [Fixnum,nil] number of bits to align after the length, if any
    # @param offset_bitlength [Fixnum,nil] (16) length in bits of the
    #   buffer's `offset` field.
    # @return [void]
    def self.data_buffer(name, bit_length = 16, padding: nil, offset_bitlength: 16)
      (@data_buffer_fields ||= []) << name

      self.unsigned "#{name}_offset", offset_bitlength, endian: 'little'
      self.unsigned "#{name}_padding", padding if padding
      self.unsigned "#{name}_length", bit_length, endian: 'little'

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

      self
    end

    ##
    # Instance methods
    ##

    # @see BitStruct#initialize
    # @yield [self] if a block is given, yields self to allow callers to modify
    #   the Packet before {#recalculate} is called
    # @yieldreturn [void]
    def initialize(*args)
      @data_buffers = {}

      # implicitly pass a block if one was given
      super

      unless data_buffer_fields.empty?
        data_buffer_fields.each do |buffer_name|
          @data_buffers[buffer_name] = self.send(buffer_name) || ""
        end
        recalculate
      end

      if self.class.const_defined?(:COMMAND)
        # Set the appropriate {#command} in the header for this packet type
        self.command = RubySMB::SMB2::COMMANDS[self.class::COMMAND]
      end
    end

    # @return [Array<String>] list of field names for {.data_buffer} fields
    def data_buffer_fields
      self.class.data_buffer_fields
    end

    #
    # @param flag [Symbol] a key in `FLAGS`
    # @raise [InvalidFlagError] when `flag` is not a member of `FLAG_NAMES`
    def has_header_flag?(flag)
      raise InvalidFlagError, flag.to_s unless HEADER_FLAG_NAMES.include?(flag)
      (header_flags & HEADER_FLAGS[flag]) == HEADER_FLAGS[flag]
    end

    # A generic flag checking method. Subclasses should have a field named
    # `flags`, and constants `FLAGS` and `FLAG_NAMES`.
    #
    # @param flag [Symbol] a key in `FLAGS`
    # @raise [InvalidFlagError] when `flag` is not a member of `FLAG_NAMES`
    def has_flag?(flag)
      raise InvalidFlagError, flag.to_s unless self.class::FLAG_NAMES.include?(flag)
      (flags & self.class::FLAGS[flag]) == self.class::FLAGS[flag]
    end

    # Fix the length and offset fields for all {.data_buffer data buffer fields}
    #
    # @return [self]
    def recalculate
      offset = self.header_len + (struct_size & ~1)
      new_buffer = ""

      data_buffer_fields.each do |buffer_name|
        @data_buffers[buffer_name] ||= ''
        new_size = @data_buffers[buffer_name].bytesize
        if new_size.zero?
          self.send("#{buffer_name}_offset=", 0)
        else
          new_buffer << @data_buffers[buffer_name]
          self.send("#{buffer_name}_length=", new_size)
          self.send("#{buffer_name}_offset=", offset)
        end
        offset += new_size
      end
      self.buffer = new_buffer.force_encoding("binary")

      self
    end

    # Sign this {Packet} with `session_key` and set the header's
    # {Request#signature signature}.
    #
    # @param session_key [String] the key to sign with
    # @return [void]
    def sign!(session_key)
      self.signature = "\0" * 16
      self.header_flags |= RubySMB::SMB2::Packet::HEADER_FLAGS[:SIGNING]

      hmac = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, session_key, self.to_s)

      self.signature = hmac[0, 16]

      self
    end

  end
end
