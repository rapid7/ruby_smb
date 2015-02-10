require 'smb2/packet'
require 'net/ntlm'
require 'net/ntlm/client'

class Smb2::Client

  attr_accessor :socket

  attr_accessor :username
  attr_accessor :password
  attr_accessor :domain

  attr_accessor :tree_ids
  attr_accessor :file_handles
  attr_accessor :session_id
  attr_accessor :sequence_number

  attr_accessor :capabilities
  attr_accessor :security_mode

  attr_accessor :state

  attr_accessor :ntlm_client

  def initialize(opts = {})
    @socket      = opts.fetch(:socket)
    @username    = opts.fetch(:username).encode("utf-8")
    @password    = opts.fetch(:password).encode("utf-8")
    @domain      = opts[:domain]
    @local_workstation = (opts[:local_workstation] || "")
  end

  def negotiate
    packet = Smb2::Packet::NegotiateRequest.new(
      dialects: "\x02\x02".b,
      dialect_count: 1,
      client_guid: 0,
    )

    send_packet(packet)
    response = recv_packet
    response_packet = Smb2::Packet::NegotiateResponse.new(response)

    @capabilities  = response_packet.capabilities
    @security_mode = response_packet.security_mode

    @state = :negotiated

    @sequence_number = 0
    # XXX do we need the Server GUID?
  end

  def authenticate
    packet = Smb2::Packet::SessionSetupRequest.new(
      security_mode: (
        @security_mode & Smb2::Packet::SECURITY_MODES[:SIGNING_ENABLED]
      ),
    )
    header = packet.header
    header.command_seq = @sequence_number += 1
    packet.header = header

    @ntlm_client = Net::NTLM::Client.new(
      username,
      password,
      workstation: @local_workstation,
      domain: @domain,
    )

    type1 = @ntlm_client.init_context

    packet.security_blob = gss_type1(type1.serialize)

    send_packet(packet)

    response = recv_packet
    response_packet = Smb2::Packet::SessionSetupResponse.new(response)

    packet = Smb2::Packet::SessionSetupRequest.new(
      security_mode: (
        @security_mode & Smb2::Packet::SECURITY_MODES[:SIGNING_ENABLED]
      ),
    )

    # copy semantics are a pain, dance around it with the reassignment polka
    header = packet.header
    header.command_seq = @sequence_number += 1
    header.session_id = response_packet.header.session_id
    packet.header = header

    @session_id = response_packet.header.session_id

    ssp_offset = response_packet.security_blob.index("NTLMSSP")
    resp_blob = response_packet.security_blob.slice(ssp_offset .. -1)

    type3 = @ntlm_client.init_context([resp_blob].pack("m"))

    @session_key = type3.session_key

    packet.security_blob = gss_type3(type3.serialize)
    send_packet(packet)
    response = recv_packet
    response_packet = Smb2::Packet::SessionSetupResponse.new(response)

    response_packet.header.nt_status
  end

  protected

  # Cargo culted from Rex
  def asn1encode(str='')
    res = ''

    # If the high bit of the first byte is 1, it contains the number of
    # length bytes that follow

    case str.length
      when 0 .. 0x7F
        res = [str.length].pack('C') + str
      when 0x80 .. 0xFF
        res = [0x81, str.length].pack('CC') + str
      when 0x100 .. 0xFFFF
        res = [0x82, str.length].pack('Cn') + str
      when  0x10000 .. 0xffffff
        res = [0x83, str.length >> 16, str.length & 0xFFFF].pack('CCn') + str
      when  0x1000000 .. 0xffffffff
        res = [0x84, str.length].pack('CN') + str
      else
        raise "ASN1 str too long"
    end

    res
  end

  def gss_type1(type1)
    "\x60".force_encoding("binary") + self.asn1encode(
      "\x06".force_encoding("binary") + self.asn1encode(
        "\x2b\x06\x01\x05\x05\x02".force_encoding("binary")
      ) +
      "\xa0".force_encoding("binary") + self.asn1encode(
        "\x30".force_encoding("binary") + self.asn1encode(
          "\xa0".force_encoding("binary") + self.asn1encode(
            "\x30".force_encoding("binary") + self.asn1encode(
              "\x06".force_encoding("binary") + self.asn1encode(
                "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a".force_encoding("binary")
              )
            )
          ) +
          "\xa2".force_encoding("binary") + self.asn1encode(
            "\x04".force_encoding("binary") + self.asn1encode(
              type1
            )
          )
        )
      )
    )
  end

  def gss_type3(type3)
    gss =
      "\xa1".force_encoding("binary") + self.asn1encode(
        "\x30".force_encoding("binary") + self.asn1encode(
          "\xa2".force_encoding("binary") + self.asn1encode(
            "\x04".force_encoding("binary") + self.asn1encode(
              type3
            )
          )
        )
      )

    gss
  end

  def nbss(packet)
    [packet.length].pack("N")
  end

  def send_packet(packet)
    data = nbss(packet) + packet.to_s
    #$stderr.write("Writing #{data.length} bytes")
    while (bytes_written = socket.send(data, 0)) < data.size
      #$stderr.write(".")
      data.slice!(0, bytes_written)
    end
    #$stderr.puts(" Done")

    nil
  end

  def recv_packet
    IO.select([socket])
    nbss_header = socket.read(4)
    if nbss_header.nil?
      raise "omg"
    else
      length = nbss_header.unpack("N").first
    end
    #$stderr.write("Reading #{length} bytes")
    IO.select([socket])
    data = socket.read(length)
    while data.length < length
      #$stderr.write(".")
      data << socket.read(length - data.length)
    end
    #$stderr.puts(" Done")

    data
  end

end
