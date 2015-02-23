require 'smb2/packet'
require 'net/ntlm'
require 'net/ntlm/client'

class Smb2::Client

  DEFAULT_SECURITY_MODE = Smb2::Packet::SECURITY_MODES[:SIGNING_ENABLED]

  # TODO: fix
  # The client's capabilities
  #
  # @return [Array]
  attr_accessor :capabilities

  attr_accessor :dispatcher

  # The ActiveDirectory domain name to associate the client with
  #
  # @return [String]
  attr_accessor :domain

  # The ActiveDirectory domain name to associate the client with
  #
  # @return [String]
  attr_accessor :file_handles

  # An NT Lan Manager client
  #
  # @return [Net::NTLM::Client]
  attr_accessor :ntlm_client

  # The ActiveDirectory password to use in authentication
  #
  # @return [String]
  attr_accessor :password

  # The session identifier returned by the server upon successful authentication
  #
  # @return [String]
  attr_accessor :session_id

  # The current sequence number, incremented as needed for new {Packet} objects
  #
  # @return [Fixnum]
  attr_accessor :sequence_number

  # TODO: URL enumerating these?
  # The server-dictated security mode, set by a successful authentication
  #
  # @return [String]
  attr_accessor :security_mode

  # The [TCPSocket]-like thing to operate on
  #
  # @return [TCPSocket]
  attr_accessor :socket

  # TODO: wat
  #
  # @return [String]
  attr_accessor :state

  # TODO: wat
  #
  # @return [String]
  attr_accessor :tree_ids

  # The ActiveDirectory username to authenticate with
  #
  # @return [String]
  attr_accessor :username

  # @option opts [#send_packet,#recv_packet] :dispatcher
  # @option opts [String] :username UTF-8
  # @option opts [String] :password UTF-8
  # @option opts [String] :domain UTF-8 *(optional)*
  # @option opts [String] :local_workstation UTF-8 *(optional)*
  # @raise KeyError if required options are missing
  def initialize(opts = {})
    @dispatcher  = opts.fetch(:dispatcher)
    @username    = opts.fetch(:username).encode("utf-8")
    @password    = opts.fetch(:password).encode("utf-8")
    @domain      = opts[:domain]
    @local_workstation = (opts[:local_workstation] || "")
  end

  # Set up an authenticated session with the server.
  #
  # Currently only supports NTLM authentication.
  #
  # @todo Kerberos, lol
  # @return [Fixnum] 32-bit NT_STATUS from the {Packet::SessionSetupResponse response}
  def authenticate
    packet = Smb2::Packet::SessionSetupRequest.new(
      security_mode: (
        @security_mode & DEFAULT_SECURITY_MODE
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

    dispatcher.send_packet(packet)

    response = dispatcher.recv_packet
    response_packet = Smb2::Packet::SessionSetupResponse.new(response)

    @session_id = response_packet.header.session_id

    packet = Smb2::Packet::SessionSetupRequest.new(
      security_mode: (
        @security_mode & DEFAULT_SECURITY_MODE
      ),
    )

    # copy semantics are a pain, dance around it with the reassignment polka
    header = packet.header
    header.command_seq = @sequence_number += 1
    header.session_id = @session_id
    packet.header = header

    ssp_offset = response_packet.security_blob.index("NTLMSSP")
    resp_blob = response_packet.security_blob.slice(ssp_offset .. -1)

    type3 = @ntlm_client.init_context([resp_blob].pack("m"))

    @session_key = type3.session_key

    packet.security_blob = gss_type3(type3.serialize)
    dispatcher.send_packet(packet)
    response = dispatcher.recv_packet
    response_packet = Smb2::Packet::SessionSetupResponse.new(response)

    response_packet.header.nt_status
  end

  # Send a {Packet::NegotiateRequest} and set up all the state required from the
  # response.
  #
  # @return [void]
  def negotiate
    packet = Smb2::Packet::NegotiateRequest.new(
      dialects: "\x02\x02".force_encoding('binary'),
      dialect_count: 1,
      client_guid: 0,
    )

    dispatcher.send_packet(packet)
    response = dispatcher.recv_packet
    response_packet = Smb2::Packet::NegotiateResponse.new(response)

    @capabilities  = response_packet.capabilities
    @security_mode = response_packet.security_mode

    @state = :negotiated

    @sequence_number = 0
    # XXX do we need the Server GUID?
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

end
