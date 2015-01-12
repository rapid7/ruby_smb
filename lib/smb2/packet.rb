require 'smb2'
require 'bit-struct'

class Smb2::Packet < BitStruct
  class InvalidFlagError < StandardError; end

  autoload :RequestHeader, "smb2/packet/request_header"
  autoload :ResponseHeader, "smb2/packet/response_header"

  autoload :NegotiateRequest, "smb2/packet/negotiate_request"
  autoload :NegotiateResponse, "smb2/packet/negotiate_response"

  autoload :SessionSetupRequest, "smb2/packet/session_setup_request"
  autoload :SessionSetupResponse, "smb2/packet/session_setup_response"

  autoload :TreeConnectRequest, "smb2/packet/tree_connect_request"
  autoload :TreeConnectResponse, "smb2/packet/tree_connect_response"

  autoload :CreateRequest, "smb2/packet/create_request"
  autoload :CreateResponse, "smb2/packet/create_response"

  autoload :WriteRequest, "smb2/packet/write_request"
  autoload :WriteResponse, "smb2/packet/write_response"

  default_options endian: 'little'

  # List of all {.data_buffer} field names
  # @return [Array<String>]
  def self.data_buffer_fields
    @data_buffer_fields ||= []
  end

  # A data buffer consisting of a 16-bit offset, 16- or 32-bit length, and a
  # value of `length` bytes at the end of the packet.
  #
  # @param name [Symbol]
  # @param bit_length [Fixnum] length in bits of the buffer's `length` field.
  # @!macro [attach] data_buffer
  #   @!attribute [rw] $1_offset
  #     @return [Fixnum] 16-bit, little-endian offset of {#$1} from the
  #       beginning of the SMB2 header
  #   @!attribute [rw] $1_length
  #     @return [Fixnum] $2-bit, little-endian length of {#$1}
  #   @!method $1
  #     @note Copy semantics, not reference
  #     @return [String] a copy of the data
  #   @!method $1=(other)
  #     Set the value of `$1` and call {#recalculate} to fix the {#$1_length
  #     length} and {#$1_offset offset}.
  #     @param other [String]
  #     @return [void]
  def self.data_buffer(name, bit_length=16)
    (@data_buffer_fields ||= []) << name

    self.unsigned "#{name}_offset", 16, endian: 'little'
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
    raise InvalidFlagError, flag.to_s unless self.class::FLAG_NAMES.include?(flag)
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
