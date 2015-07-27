require 'net/ntlm'
require 'net/ntlm/client'
require 'windows_error'
require 'windows_error/nt_status'

# A client for holding the state of an SMB2 session.
#
#
# @example Connect and authenticate
#   sock = TCPSocket.new("192.168.100.140", 445)
#   c = RubySMB::Smb2::Client.new(
#     socket: sock,
#     username:"administrator",
#     password:"P@ssword1",
#     domain:"asdfasdf"
#   )
#   c.negotiate
#   c.authenticate
#
#
class RubySMB::Smb2::Client

  # @see RubySMB::Smb2::Packet::SECURITY_MODES
  # @return [Fixnum]
  DEFAULT_SECURITY_MODE = RubySMB::Smb2::Packet::SECURITY_MODES[:SIGNING_ENABLED]

  # The client's capabilities
  #
  # @see Packet::SessionSetupRequest#capabilities
  # @return [Fixnum]
  attr_accessor :capabilities

  # The negotiated dialect. Before {#negotiate negotiation}, this will be nil.
  #
  # @see Packet::SessionSetupResponse#dialect_revision
  # @return [Fixnum]
  attr_accessor :dialect

  # @return [RubySMB::Smb2::Dispatcher,#send_packet,#recv_packet]
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

  # @param dispatcher [#send_packet,#recv_packet]
  # @param username [String] UTF-8
  # @param password [String] UTF-8
  # @param domain [String] UTF-8
  # @param local_workstation [String] UTF-8
  def initialize(dispatcher:, username:, password:, domain: nil, local_workstation: "")
    @dialect     = nil
    @dispatcher  = dispatcher
    @domain      = domain
    @local_workstation = local_workstation
    @password    = password.encode("utf-8")
    @session_id  = nil
    @username    = username.encode("utf-8")
  end

  # Set up an authenticated session with the server.
  #
  # Currently only supports NTLM authentication.
  #
  # @todo Kerberos, lol
  # @return [WindowsError::ErrorCode] 32-bit NT_STATUS from the {Packet::SessionSetupResponse response}
  def authenticate
    @ntlm_client = Net::NTLM::Client.new(
      username,
      password,
      workstation: @local_workstation,
      domain: @domain
    )
    response = ntlmssp_negotiate
    @session_id = response.session_id
    response = ntlmssp_auth(response)

    if response.nt_status == WindowsError::NTStatus::STATUS_SUCCESS
      @state = :authenticated
    else
      @state = :authentication_failed
    end

    WindowsError::NTStatus.find_by_retval(response.nt_status)
  end

  def inspect
    info = @state.to_s
    if dialect
      info += " 0x#{dialect.to_s(16)}"
    end
    "#<#{self.class} #{info}>"
  end

  # Send a {Packet::NegotiateRequest} and set up all the state required from the
  # response.
  #
  # @return [void]
  def negotiate
    packet = RubySMB::Smb2::Packet::NegotiateRequest.new(
      dialects: "\x02\x02".force_encoding('binary'),
      dialect_count: 1,
      client_guid: 0,
      security_mode: DEFAULT_SECURITY_MODE,
    )

    response = send_recv(packet)

    @capabilities = response.capabilities
    @dialect = response.dialect_revision
    @max_read_size = response.max_read_size
    @max_transaction_size = response.max_transaction_size
    @max_write_size = response.max_write_size

    @security_mode = DEFAULT_SECURITY_MODE | response.security_mode

    @state = :negotiated

    # XXX do we need the Server GUID?
    response
  end

  # Sends a {SessionSetupRequest} packet with the
  # NTLMSSP_AUTH data to complete authentication handshake.
  #
  # @param challenge [RubySMB::Smb2::Packet::SessionSetupResponse]  the response packet from #ntlmssp_negotiate
  # @return [RubySMB::Smb2::Packet::SessionSetupResponse] the final SessionSetup Response packet
  def ntlmssp_auth(challenge)
    packet = RubySMB::Smb2::Packet::SessionSetupRequest.new(
      security_mode: security_mode,
    )

    ssp_offset = challenge.security_blob.index("NTLMSSP")
    resp_blob = challenge.security_blob.slice(ssp_offset..-1)

    type3 = @ntlm_client.init_context([resp_blob].pack("m"))

    packet.security_blob = gss_type3(type3.serialize)
    send_recv(packet)
  end

  # Sends a {SessionSetupRequest} packet with the
  # NTLMSSP_NEGOTIATE data to initiate authentication handshake.
  #
  # @return [RubySMB::Smb2::Packet::SessionSetupResponse] the first SessionSetup Response packet
  def ntlmssp_negotiate
    packet = RubySMB::Smb2::Packet::SessionSetupRequest.new(
      security_mode: security_mode,
    )
    type1 = @ntlm_client.init_context
    packet.security_blob = gss_type1(type1.serialize)
    send_recv(packet)
  end

  # Adjust `request`'s header with an appropriate sequence number and session
  # id, then send it and wait for a response.
  #
  # @return (see Dispatcher::Socket#recv_packet)
  def send_recv(request)
    # negative to avoid complicating the increment below
    @sequence_number ||= -1

    # Adjust header with sequence number and session id if we have one
    request.command_seq = @sequence_number += 1
    request.session_id  = @session_id if @session_id

    # Sign the packet if necessary.
    # THIS MUST BE THE LAST THING WE DO BEFORE SENDING
    if @session_id && signing_required? && !request.kind_of?(RubySMB::Smb2::Packet::SessionSetupRequest)
      request.sign!(session_key)
    end

    dispatcher.send_packet(request)
    dispatcher.recv_packet
  end

  # Signing key as supplied by the underlying authentication mechanism (just
  # NTLMSSP right now)
  #
  # @return [String] binary-encoded String for use in {Packet#sign! packet signing}
  def session_key
    @ntlm_client.session_key
  end

  # Whether this session has negotiated required signing
  #
  # |                         | Server Required | Server Not Required |
  # | ----------------------- |:---------------:|:-------------------:|
  # | **Client Required**     | Signed          | Signed              |
  # | **Client Not Required** | Signed          | Not Signed          |
  #
  # @see http://blogs.technet.com/b/josebda/archive/2010/12/01/the-basics-of-smb-signing-covering-both-smb1-and-smb2.aspx
  def signing_required?
    RubySMB::Smb2::Packet::SECURITY_MODES[:SIGNING_REQUIRED] ==
      (security_mode & RubySMB::Smb2::Packet::SECURITY_MODES[:SIGNING_REQUIRED])
  end

  # Connect to a share
  #
  # @param tree [String] Something like "\\\\hostname\\tree"
  # @return [RubySMB::Smb2::Tree]
  def tree_connect(tree)
    packet = RubySMB::Smb2::Packet::TreeConnectRequest.new(
      tree: tree.encode("utf-16le")
    )

    response = send_recv(packet)

    RubySMB::Smb2::Tree.new(client: self, share: tree, tree_connect_response: response)
  end

  protected

  # Cargo culted from Rex
  def asn1encode(str = '')
    res = ''

    # If the high bit of the first byte is 1, it contains the number of
    # length bytes that follow

    case str.length
    when 0..0x7F
      res = [str.length].pack('C') + str
    when 0x80..0xFF
      res = [0x81, str.length].pack('CC') + str
    when 0x100..0xFFFF
      res = [0x82, str.length].pack('Cn') + str
    when  0x10000..0xffffff
      res = [0x83, str.length >> 16, str.length & 0xFFFF].pack('CCn') + str
    when  0x1000000..0xffffffff
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
