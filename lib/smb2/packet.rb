require 'smb2'
require 'bit-struct'

class Smb2::Packet < BitStruct

  autoload :RequestHeader,  "smb2/packet/request_header"

  autoload :SessionSetupRequest,  "smb2/packet/session_setup_request"
  autoload :SessionSetupResponse, "smb2/packet/session_setup_response"

  # @!macro [attach] nest
  #   @!attribute [rw] $1
  #     @return [$2]
  def self.nest(*args); super; end

  # @!macro [attach] signed
  #   @!attribute [rw] $1
  #     @return [Fixnum] $2-bit signed value
  def self.signed(*args); super; end

  # @!macro [attach] string
  #   @!attribute [rw] $1
  #     @return [String] Raw bytes
  def self.string(*args); super; end

  # @!macro [attach] unsigned
  #   @!attribute [rw] $1
  #     @return [Fixnum] $2-bit unsigned value
  def self.unsigned(*args); super; end

  # A data buffer consisting of a 16-bit offset, a 16-bit length, and a value
  # of `length` bytes at the end of the packet.
  #
  # @!macro [attach] data_buffer
  #   @!attribute [rw] $1_offset
  #     @return [Fixnum] 16-bit, little-endian offset of {#$1} from the
  #       beginning of the SMB2 header
  #   @!attribute [rw] $1_length
  #     @return [Fixnum] 16-bit, little-endian length of {#$1}
  #   @!attribute [rw] $1
  #     @return [String]
  def self.data_buffer(name)
    (@data_buffers ||= []) << name

    self.unsigned "#{name}_offset", 16, endian: 'little'
    self.unsigned "#{name}_length", 16, endian: 'little'
    unless self.field_by_name(:data)
      self.rest :data
    end

    class_eval do
      define_method(name) do
        self[self.send("#{name}_offset"), self.send("#{name}_length")]
      end
      # TODO add setter
      #define_method(name + "=") do |other|
      #  recalculate
      #end
    end

    self
  end

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
