require 'smb2'
require 'bit-struct'

class Smb2::Packet < BitStruct
  class InvalidFlagError < StandardError; end

  autoload :RequestHeader,  "smb2/packet/request_header"
  autoload :ResponseHeader,  "smb2/packet/response_header"

  autoload :SessionSetupRequest,  "smb2/packet/session_setup_request"
  autoload :SessionSetupResponse, "smb2/packet/session_setup_response"

  autoload :TreeConnectRequest,  "smb2/packet/tree_connect_request"
  autoload :TreeConnectResponse,  "smb2/packet/tree_connect_response"


  # A data buffer consisting of a 16-bit offset, a 16-bit length, and a value
  # of `length` bytes at the end of the packet.
  #
  # @!macro [attach] data_buffer
  #   @!attribute [rw] $1_offset
  #     @return [Fixnum] 16-bit, little-endian offset of {#$1} from the
  #       beginning of the SMB2 header
  #   @!attribute [rw] $1_length
  #     @return [Fixnum] 16-bit, little-endian length of {#$1}
  #   @!attribute [r] $1
  #     @note Copy semantics, not reference
  #     @return [String]
  def self.data_buffer(name)
    (@data_buffers ||= []) << name

    self.unsigned "#{name}_offset", 16, endian: 'little'
    self.unsigned "#{name}_length", 16, endian: 'little'
    unless self.rest_field
      self.rest :data
    end

    class_eval do
      define_method(name) do
        to_s.slice(self.send("#{name}_offset"), self.send("#{name}_length"))
      end
      # TODO add setter
      #define_method(name + "=") do |other|
      #  recalculate
      #end
    end

    self
  end

  # A generic flag checking method. Subclasses should have a field named
  # `flags`, and constants `FLAGS` and `FLAG_NAMES`.
  #
  # @param flag [Symbol] a key in `FLAGS`
  def has_flag?(flag)
    raise InvalidFlagError, flag.to_s unless self.class::FLAG_NAMES.include?(flag)
    (flags & self.class::FLAGS[flag]) == self.class::FLAGS[flag]
  end

  # Fix the length and offset fields for all {.data_buffer data buffers}
  #
  # @return [self]
  def recalculate
    offset = 0
    data_buffers.each do |buffer_name|
      new_size = self.public_send(buffer_name).size
      self.public_send("#{buffer_name}_length=", new_size)
      self.public_send("#{buffer_name}_offset=", offset)
      offset += new_size
    end

    self
  end

end
