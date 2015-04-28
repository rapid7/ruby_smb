require 'net/ntlm'
require 'net/ntlm/client'

# A client for holding the state of an SMB2 session.
#
#
# @example Connect and authenticate
#   sock = TCPSocket.new("192.168.100.140", 445)
#   c = Smb2::Client.new(
#     socket: sock,
#     username:"administrator",
#     password:"P@ssword1",
#     domain:"asdfasdf"
#   )
#   c.negotiate
#   c.authenticate
#
#
class Smb2::Client

  # This mode will be bitwise AND'd with the value from the server
  DEFAULT_SECURITY_MODE = Smb2::Packet::SECURITY_MODES[:SIGNING_ENABLED]

  # The client's capabilities
  #
  # @see Packet::SessionSetupRequest#capabilities
  # @return [Fixnum]
  attr_accessor :capabilities

  # @return [Smb2::Dispatcher,#send_packet,#recv_packet]
  attr_accessor :dispatcher

  # The ActiveDirectory domain name to associate the client with
  #
  # @return [String]
  attr_accessor :domain

  # Largest value usable in {Packet::ReadRequest#read_length}. Anything bigger
  # than this will result in a STATUS_INVALID_PARAMETER when reading.
  # @return [Fixnum]
  attr_accessor :max_read_size

  # @return [Fixnum]
  attr_accessor :max_transaction_size

  # @return [Fixnum]
  attr_accessor :max_write_size

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
  # @return [Fixnum]
  attr_accessor :security_mode

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

    @tree_ids = []
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

    @ntlm_client = Net::NTLM::Client.new(
      username,
      password,
      workstation: @local_workstation,
      domain: @domain,
    )

    type1 = @ntlm_client.init_context

    packet.security_blob = gss_type1(type1.serialize)

    response = send_recv(packet)
    response_packet = Smb2::Packet::SessionSetupResponse.new(response)

    @session_id = response_packet.header.session_id

    packet = Smb2::Packet::SessionSetupRequest.new(
      security_mode: (
        @security_mode & DEFAULT_SECURITY_MODE
      ),
    )

    ssp_offset = response_packet.security_blob.index("NTLMSSP")
    resp_blob = response_packet.security_blob.slice(ssp_offset .. -1)

    type3 = @ntlm_client.init_context([resp_blob].pack("m"))

    @session_key = type3.session_key

    packet.security_blob = gss_type3(type3.serialize)
    response = send_recv(packet)
    response_packet = Smb2::Packet::SessionSetupResponse.new(response)

    if response_packet.header.nt_status == 0
      @state = :authenticated
    end

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

    response = send_recv(packet)
    response_packet = Smb2::Packet::NegotiateResponse.new(response)

    @capabilities  = response_packet.capabilities
    @security_mode = response_packet.security_mode
    @max_read_size = response_packet.max_read_size
    @max_transaction_size = response_packet.max_transaction_size
    @max_write_size = response_packet.max_write_size

    @state = :negotiated

    # XXX do we need the Server GUID?
    response_packet
  end

  # Adjust `request`'s header with an appropriate sequence number and session
  # id, then send it and wait for a response.
  #
  # @return (see Dispatcher::Socket#recv_packet)
  def send_recv(request)
    # negative to avoid complicating the increment below
    @sequence_number ||= -1

    # Adjust header
    header = request.header
    header.command_seq = @sequence_number += 1
    if @session_id
      header.session_id = @session_id
    end
    request.header = header

    dispatcher.send_packet(request)

    dispatcher.recv_packet
  end

  # @param tree [String]
  # @return [Smb2::Tree]
  def tree_connect(tree)
    packet = Smb2::Packet::TreeConnectRequest.new do |request|
      request.tree = tree.encode("utf-16le")
    end

    response = send_recv(packet)
    response_packet = Smb2::Packet::TreeConnectResponse.new(response)

    Smb2::Tree.new(client: self, tree_connect_response: response_packet)
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
