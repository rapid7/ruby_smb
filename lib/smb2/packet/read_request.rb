require 'smb2/packet'

class Smb2::Packet
  # [Section 2.2.19 SMB2 Read Request](https://msdn.microsoft.com/en-us/library/cc246527.aspx)
  #
  # [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
  class ReadRequest < Smb2::Packet
    nest :header, RequestHeader

    unsigned :struct_size, 16, default: 49

    # > The requested offset from the start of the SMB2 header, in bytes, at
    #   which to place the data read in the SMB2 READ Response (section 2.2.20).
    #   This value is provided to optimize data placement on the client and is
    #   not binding on the server.
    unsigned :padding, 8

    # Flags
    #
    # > For the SMB 2.002, 2.1 and 3.0 dialects, this field MUST NOT be used
    #   and MUST be reserved. The client MUST set this field to 0, and the
    #   server MUST ignore it on receipt. For the SMB 3.02 dialect, this field
    #   MUST contain zero or more of the following values:
    #
    # | Value | Meaning |
    # | ----- | ------- |
    # | SMB2_READFLAG_READ_UNBUFFERED 0x01 | The server or underlying object store SHOULD NOT cache the read data at intermediate layers.
    #
    # @see FLAGS
    unsigned :flags, 8

    # > The length, in bytes, of the data to read from the specified file or
    #   pipe. The length of the data being read may be zero bytes
    unsigned :read_length, 32

    # > The offset, in bytes, into the file from which the data MUST be read. If
    #   the read is being executed on a pipe, the Offset MUST be set to 0 by the
    #   client and MUST be ignored by the server.
    unsigned :read_offset, 64

    string :file_id, 128

    # > The minimum number of bytes to be read for this operation to be
    #   successful. If fewer than the minimum number of bytes are read by the
    #   server, the server MUST return an error rather than the bytes read.
    unsigned :minimum_count, 32

    unsigned :channel, 32

    unsigned :remaining_bytes, 32

    unsigned :read_channel_info_offset, 16
    unsigned :read_channel_info_length, 16

    # Can't use a `data_buffer` for read_channel_info because unlike all other
    # data buffers, this one must have at least one NULL byte.
    #
    # @see https://msdn.microsoft.com/en-us/library/cc246527.aspx
    # > Buffer (variable): A variable-length buffer that contains the read
    #   channel information, as described by ReadChannelInfoOffset and
    #   ReadChannelInfoLength. Unused at present. The client MUST set one byte
    #   of this field to 0, and the server MUST ignore it on receipt
    #
    # @note Updating this will *NOT* change {#read_channel_info_length} or
    #   {#read_channel_info_offset}
    string :read_channel_info, 8, default: "\x00".force_encoding('binary')

    FLAGS = {
      READ_UNBUFFERED: 0x01
    }.freeze

    # @return [Symbol] a key in {Smb2::COMMANDS}
    def self.command
      :READ
    end
  end
end

