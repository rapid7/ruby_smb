require 'ruby_smb/dcerpc/client'

RSpec.describe RubySMB::Dcerpc::Client do
  it 'includes the RubySMB::Dcerpc::Epm class' do
    expect(described_class < RubySMB::Dcerpc::Epm).to be true
  end

  let(:host)     { '1.2.3.4' }
  let(:endpoint) { RubySMB::Dcerpc::Samr }

  subject(:client) { described_class.new(host, endpoint) }
  subject(:auth_client) { described_class.new(host, endpoint, username: 'testuser', password: '1234') }

  it { is_expected.to respond_to :domain }
  it { is_expected.to respond_to :local_workstation }
  it { is_expected.to respond_to :ntlm_client }
  it { is_expected.to respond_to :username }
  it { is_expected.to respond_to :password }
  it { is_expected.to respond_to :default_name }
  it { is_expected.to respond_to :default_domain }
  it { is_expected.to respond_to :dns_host_name }
  it { is_expected.to respond_to :dns_domain_name }
  it { is_expected.to respond_to :dns_tree_name }
  it { is_expected.to respond_to :os_version }
  it { is_expected.to respond_to :max_buffer_size }
  it { is_expected.to respond_to :tcp_socket }

  describe '#auth_ctx_id_base' do
    it 'is randomly generated' do
      expect(
        20.times.map do
          described_class.new(host, endpoint).instance_variable_get(:@auth_ctx_id_base)
        end.uniq.size
      ).to eq(20)
    end
  end

  describe '#ntlm_client' do
    context 'without a username and a password' do
      it 'does not instantiate a net::ntlm::client' do
        expect(client.ntlm_client).to be nil
      end
    end

    context 'with a username and a password' do
      it 'instantiates a Net::NTLM::Client' do
        expect(auth_client.ntlm_client).to be_a Net::NTLM::Client
      end
    end
  end

  describe '#connect' do
    let(:tcp_socket) { double('TcpSocket') }
    before :example do
      allow(TCPSocket).to receive(:new).and_return(tcp_socket)
    end

    it 'does nothing if a TcpSocket has been provided already' do
      client.tcp_socket = double('TcpSocket')
      expect(client.connect).to be nil
      expect(TCPSocket).to_not have_received(:new)
    end

    context 'without initial TcpSocket' do
      context 'when a TCP port is provided' do
        it 'connects to this port' do
          expect(client.connect(port: 123)).to eq(tcp_socket)
          expect(TCPSocket).to have_received(:new).with(host, 123)
        end
      end

      context 'without TCP port' do
        let(:host_port) { {host: '0.9.8.7', port: 999} }
        let(:epm_tcp_socket) { double('EPM TcpSocket') }
        before :example do
          allow(TCPSocket).to receive(:new).with(host, 135).and_return(epm_tcp_socket)
          allow(client).to receive(:bind)
          allow(client).to receive(:get_host_port_from_ept_mapper).and_return(host_port)
          allow(epm_tcp_socket).to receive(:close)
        end

        it 'connects to port 135' do
          client.connect
          expect(TCPSocket).to have_received(:new).with(host, 135)
        end

        it 'binds to the Endpoint Mapper endpoint' do
          client.connect
          expect(client).to have_received(:bind).with(endpoint: RubySMB::Dcerpc::Epm)
        end

        it 'gets host and port information from the Endpoint Mapper' do
          client.connect
          expect(client).to have_received(:get_host_port_from_ept_mapper).with(
            uuid: endpoint::UUID,
            maj_ver: endpoint::VER_MAJOR,
            min_ver: endpoint::VER_MINOR
          )
        end

        it 'closes the EPM socket' do
          client.connect
          expect(epm_tcp_socket).to have_received(:close)
        end

        it 'connects to the endpoint and returns the socket' do
          expect(client.connect).to eq(tcp_socket)
          expect(TCPSocket).to have_received(:new).with(host, 999)
        end
      end
    end
  end

  describe '#close' do
    let(:tcp_socket) { double('TcpSocket') }
    before :example do
      client.tcp_socket = tcp_socket
      allow(tcp_socket).to receive(:close)
    end

    it 'closes the socket' do
      allow(tcp_socket).to receive(:closed?).and_return(false)
      client.close
      expect(tcp_socket).to have_received(:close)
    end

    it 'does not closes the socket if it is already closed' do
      allow(tcp_socket).to receive(:closed?).and_return(true)
      client.close
      expect(tcp_socket).to_not have_received(:close)
    end
  end

  context 'with authentication' do
    describe '#add_auth_verifier' do
      let(:req) { RubySMB::Dcerpc::Bind.new }
      let(:auth_type) { RubySMB::Dcerpc::RPC_C_AUTHN_WINNT }
      let(:auth_level) { 0 }
      let(:auth) { 'serialized auth value' }

      it 'sets #auth_value field to the expected value' do
        auth_client.add_auth_verifier(req, auth, auth_type, auth_level)
        expect(req.auth_value).to eq(auth)
      end

      it 'sets PDUHeader #auth_length field to the expected value' do
        auth_client.add_auth_verifier(req, auth, auth_type, auth_level)
        expect(req.pdu_header.auth_length).to eq(auth.length)
      end

      it 'sets #sec_trailer field to the expected value' do
        auth_client.add_auth_verifier(req, auth, auth_type, auth_level)
        expect(req.sec_trailer.auth_type).to eq(auth_type)
        expect(req.sec_trailer.auth_level).to eq(auth_level)
        expect(req.sec_trailer.auth_context_id).to eq(auth_client.instance_variable_get(:@auth_ctx_id_base))
      end
    end

    describe '#process_ntlm_type2' do
      let(:type2_message) do
        '4e544c4d53535000020000000a000a0038000000358289e2e7acb2d8d2f0e12100000000000000'\
        '00aa00aa00420000000602f0230000000f4d0059004c004100420002000a004d0059004c004100'\
        '420001001c00570049004e002d004400500030004d00310042004300370036003800040016006d'\
        '0079006c00610062002e006c006f00630061006c0003003400570049004e002d00440050003000'\
        '4d003100420043003700360038002e006d0079006c00610062002e006c006f00630061006c0005'\
        '0016006d0079006c00610062002e006c006f00630061006c0007000800c0ff2034bd95d7010000'\
        '0000'.unhexlify
      end

      it 'returns the expected type3 message' do
        expect(auth_client.process_ntlm_type2(type2_message)).to start_with("NTLMSSP\x00\x03\x00\x00\x00")
      end

      it 'stores the session key' do
        auth_client.process_ntlm_type2(type2_message)
        expect(auth_client.instance_variable_get(:@session_key).size).to eq(16)
      end

      it 'stores the target information' do
        expect(auth_client).to receive(:store_target_info)
        auth_client.process_ntlm_type2(type2_message)
      end

      it 'stores the OS version' do
        auth_client.process_ntlm_type2(type2_message)
        expect(auth_client.os_version).to eq('6.2.9200')
      end
    end

    describe '#send_auth3' do
      let(:auth) { 'NTLMSSP security blob' }
      let(:bindack) { RubySMB::Dcerpc::BindAck.new(auth_value: auth) }
      let(:auth_type) { RubySMB::Dcerpc::RPC_C_AUTHN_WINNT }
      let(:auth_level) { 0 }
      let(:auth3) { double('Type3 message') }
      let(:rpc_auth3) { RubySMB::Dcerpc::RpcAuth3.new }
      before :example do
        allow(auth_client).to receive(:process_ntlm_type2).and_return(auth3)
        allow(RubySMB::Dcerpc::RpcAuth3).to receive(:new).and_return(rpc_auth3)
        allow(auth_client).to receive(:add_auth_verifier)
        allow(auth_client).to receive(:send_packet)
      end

      it 'add an auth verifier to the RpcAuth3 packet' do
        auth_client.send_auth3(bindack, auth_type, auth_level)
        expect(auth_client).to have_received(:add_auth_verifier).with(rpc_auth3, auth3, auth_type, auth_level)
      end

      it 'sets the PDUHeader #call_id to the expected value' do
        auth_client.instance_variable_set(:@call_id, 56)
        auth_client.send_auth3(bindack, auth_type, auth_level)
        expect(rpc_auth3.pdu_header.call_id).to eq(56)
      end

      it 'sends the RpcAuth3 packet' do
        auth_client.send_auth3(bindack, auth_type, auth_level)
        expect(auth_client).to have_received(:send_packet).with(rpc_auth3)
      end

      it 'increments #call_id' do
        auth_client.send_auth3(bindack, auth_type, auth_level)
        expect(auth_client.instance_variable_get(:@call_id)).to eq(2)
      end

      context 'with RPC_C_AUTHN_WINNT auth_type' do
        it 'processes NTLM type2 message' do
          auth_client.send_auth3(bindack, auth_type, auth_level)
          expect(auth_client).to have_received(:process_ntlm_type2).with(auth)
        end
      end
    end
  end

  describe '#bind' do
    let(:bind_req) { RubySMB::Dcerpc::Bind.new(endpoint: endpoint) }
    let(:bindack_response) do
      RubySMB::Dcerpc::BindAck.new({
        p_result_list: {
          p_results: [{
            result: RubySMB::Dcerpc::BindAck::ACCEPTANCE
          }]
        }
      })
    end
    before :example do
      allow(RubySMB::Dcerpc::Bind).to receive(:new).and_return(bind_req)
      allow(client).to receive(:send_packet)
      allow(client).to receive(:recv_struct).and_return(bindack_response)
    end

    it 'sets the expected call_id value on the Bind request' do
      client.instance_variable_set(:@call_id, 56)
      client.bind
      expect(bind_req.pdu_header.call_id).to eq(56)
    end

    it 'sends the expected Bind packet' do
      client.bind
      expect(client).to have_received(:send_packet).with(bind_req)
    end

    context 'without presentation context in the response' do
      let(:bindack_response) { RubySMB::Dcerpc::BindAck.new }

      it 'raises a BindError exception' do
        expect { client.bind }.to raise_error(RubySMB::Dcerpc::Error::BindError)
      end
    end

    context 'with a response that refused the presentation context' do
      let(:bindack_response) do
        RubySMB::Dcerpc::BindAck.new({
          p_result_list: {
            p_results: [{
              result: RubySMB::Dcerpc::BindAck::PROVIDER_REJECTION
            }]
          }
        })
      end

      it 'raises a BindError exception' do
        expect { client.bind }.to raise_error(RubySMB::Dcerpc::Error::BindError)
      end
    end

    it 'sets @max_buffer_size from the response value' do
      bindack_response.max_xmit_frag = 12345
      client.bind
      expect(client.max_buffer_size).to eq(12345)
    end

    it 'sets @call_id from the response value' do
      bindack_response.pdu_header.call_id = 45
      client.bind
      expect(client.instance_variable_get(:@call_id)).to eq(45)
    end

    context 'with authentication' do
      subject(:client) { described_class.new(host, endpoint, username: 'testuser', password: '1234') }

      context 'with RPC_C_AUTHN_WINNT auth_type' do
        let(:kwargs) do {
            auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_DEFAULT,
            auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
          }
        end
        let(:type1_message) { double('type1 message') }
        let(:auth) { double('auth') }
        before :example do
          allow(client.ntlm_client).to receive(:init_context).and_return(type1_message)
          allow(type1_message).to receive(:serialize).and_return(auth)
          allow(client).to receive(:add_auth_verifier)
          allow(client).to receive(:send_auth3)
        end

        it 'raises an exception if the NTLM client is not initialized' do
          client.ntlm_client = nil
          expect {client.bind(**kwargs)}.to raise_error(ArgumentError)
        end

        it 'adds the auth verifier with a NTLM type1 message' do
          client.bind(**kwargs)
          expect(client).to have_received(:add_auth_verifier).with(bind_req, auth, kwargs[:auth_type], kwargs[:auth_level])
        end

        it 'sends an auth3 request' do
          client.bind(**kwargs)
          expect(client).to have_received(:send_auth3).with(bindack_response, kwargs[:auth_type], kwargs[:auth_level])
        end
      end
    end
  end

  describe '#store_target_info' do
    let(:target_info_str) do
      '02001400540045005300540044004f004d00410049004e000100100054004500530054004e0041'\
      '004d00450004002000740065007300740064006f006d00610069006e002e006c006f0063006100'\
      '6c000300320074006500730074006e0061006d0065002e00740065007300740064006f006d0061'\
      '0069006e002e006c006f00630061006c0005002000740065007300740066006f00720065007300'\
      '74002e006c006f00630061006c0007000800513777014668d30100000000'.unhexlify
    end

    it 'creates a Net::NTLM::TargetInfo object from the target_info string' do
      expect(Net::NTLM::TargetInfo).to receive(:new).with(target_info_str).and_call_original
      client.store_target_info(target_info_str)
    end

    it 'sets the expected Client\'s attribute' do
      client.store_target_info(target_info_str)
      expect(client.default_name).to eq 'TESTNAME'
      expect(client.default_domain).to eq 'TESTDOMAIN'
      expect(client.dns_host_name).to eq 'testname.testdomain.local'
      expect(client.dns_domain_name).to eq 'testdomain.local'
      expect(client.dns_tree_name).to eq 'testforest.local'
    end

    it 'stores the strings with UTF-8 encoding' do
      client.store_target_info(target_info_str)
      expect(client.default_name.encoding.name).to eq 'UTF-8'
      expect(client.default_domain.encoding.name).to eq 'UTF-8'
      expect(client.dns_host_name.encoding.name).to eq 'UTF-8'
      expect(client.dns_domain_name.encoding.name).to eq 'UTF-8'
      expect(client.dns_tree_name.encoding.name).to eq 'UTF-8'
    end
  end

  describe '#extract_os_version' do
    it 'returns the expected version number' do
      expect(client.extract_os_version("\x06\x00q\x17\x00\x00\x00\x0F")).to eq '6.0.6001'
    end
  end

  describe '#set_integrity_privacy' do
    let(:dcerpc_req) do
      RubySMB::Dcerpc::Request.new(
        { opnum: RubySMB::Dcerpc::Winreg::REG_ENUM_KEY },
        { endpoint: 'Winreg' }
      )
    end
    let(:auth_level) { RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY }
    let(:auth_type) { RubySMB::Dcerpc::RPC_C_AUTHN_WINNT }
    let(:session) { double('NTLM Session') }
    let(:encrypted_stub) { 'Encrypted Stub'.b }
    let(:auth_pad) { "\x00" * dcerpc_req.sec_trailer.auth_pad_length.to_i }
    let(:signature) { 'Signature'.b }
    before :example do
      allow(auth_client.ntlm_client).to receive(:session).and_return(session)
      # Make sure the encrypted stub includes the correct pad to make sure sec_trailer is 16-bytes aligned
      allow(session).to receive(:seal_message).and_return(encrypted_stub + auth_pad)
      allow(session).to receive(:sign_message).and_return(signature)
    end

    it 'sets the sec_trailer to the correct values' do
      auth_client.set_integrity_privacy(dcerpc_req, auth_level: auth_level, auth_type: auth_type)
      expect(dcerpc_req.sec_trailer.auth_type).to eq(auth_type)
      expect(dcerpc_req.sec_trailer.auth_level).to eq(auth_level)
      expect(dcerpc_req.sec_trailer.auth_context_id).to eq(auth_client.instance_variable_get(:@auth_ctx_id_base))
    end

    it 'sets the PDU header auth_length field to the signature size' do
      auth_client.set_integrity_privacy(dcerpc_req, auth_level: auth_level, auth_type: auth_type)
      expect(dcerpc_req.pdu_header.auth_length).to eq(signature.size)
    end

    it 'signs the correct message' do
      plain_stub = dcerpc_req.stub.to_binary_s
      auth_client.set_integrity_privacy(dcerpc_req, auth_level: auth_level, auth_type: auth_type)
      expect(dcerpc_req.auth_value).to eq(signature)
      expect(dcerpc_req.pdu_header.auth_length).to eq(signature.size)

      # Restore the request structure to what it was before signing:
      # First, remove the signature but keep the PDU header auth_length value
      dcerpc_req.auth_value = ''
      dcerpc_req.pdu_header.auth_length = 16
      # Restore the plaintext stub
      dcerpc_req.stub = plain_stub
      # Restore the original fragment length: packet.size + original_signature.size
      dcerpc_req.pdu_header.frag_length = dcerpc_req.num_bytes + 16
      expect(session).to have_received(:sign_message).with(dcerpc_req.to_binary_s)
    end

    context 'without NTLM EXTENDED_SECURITY flag' do
      it 'signs the correct message' do
        flags = auth_client.ntlm_client.flags ^ RubySMB::NTLM::NEGOTIATE_FLAGS[:EXTENDED_SECURITY]
        allow(auth_client.ntlm_client).to receive(:flags).and_return(flags)
        plain_stub = dcerpc_req.stub.to_binary_s
        auth_client.set_integrity_privacy(dcerpc_req, auth_level: auth_level, auth_type: auth_type)
        expect(dcerpc_req.auth_value).to eq(signature)
        expect(dcerpc_req.pdu_header.auth_length).to eq(signature.size)
        expect(session).to have_received(:sign_message).with(plain_stub + auth_pad)
      end
    end

    it 'encrypts the stub' do
      plain_stub = dcerpc_req.stub.to_binary_s + dcerpc_req.auth_pad.to_binary_s
      auth_client.set_integrity_privacy(dcerpc_req, auth_level: auth_level, auth_type: auth_type)
      expect(dcerpc_req.stub).to eq(encrypted_stub)
      expect(session).to have_received(:seal_message).with(plain_stub)
    end

    context 'without RPC_C_AUTHN_LEVEL_PKT_PRIVACY auth_level' do
      it 'does not encrypt the stub' do
        plain_stub = dcerpc_req.stub.to_binary_s
        auth_client.set_integrity_privacy(dcerpc_req, auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, auth_type: auth_type)
        expect(dcerpc_req.stub.to_binary_s).to eq(plain_stub)
        expect(session).to_not have_received(:seal_message)
      end
    end

    context 'with an unsupported auth_level' do
      it 'raises an Argument exception' do
        expect { auth_client.set_integrity_privacy(dcerpc_req, auth_level: auth_level, auth_type: 88) }.to raise_error(ArgumentError)
      end
    end
  end

  describe '#dcerpc_request' do
    let(:request_stub) { RubySMB::Dcerpc::Winreg::EnumKeyRequest.new(lp_name: 'Test Name Request') }
    let(:dcerpc_req) do
      RubySMB::Dcerpc::Request.new(
        { opnum: RubySMB::Dcerpc::Winreg::REG_ENUM_KEY },
        { endpoint: endpoint }
      )
    end
    let(:response_stub) { RubySMB::Dcerpc::Winreg::EnumKeyResponse.new(lp_name: 'Test Name Response') }
    let(:dcerpc_res) { RubySMB::Dcerpc::Response.new(stub: response_stub.to_binary_s) }
    before :example do
      allow(RubySMB::Dcerpc::Request).to receive(:new).and_return(dcerpc_req)
      allow(client).to receive(:send_packet)
      allow(client).to receive(:recv_struct).and_return(dcerpc_res)
    end

    it 'returns the correct response stub' do
      expect(client.dcerpc_request(request_stub)).to eq(response_stub.to_binary_s)
    end

    it 'sends the correct Request packet' do
      client.dcerpc_request(request_stub)
      expect(client).to have_received(:send_packet).with(dcerpc_req)
    end

    it 'receives the correct packet' do
      client.dcerpc_request(request_stub)
      expect(client).to have_received(:recv_struct).with(RubySMB::Dcerpc::Response)
    end

    context 'when the first packet is not the first fragment' do
      it 'raises an InvalidPacket exception' do
        dcerpc_res.pdu_header.pfc_flags.first_frag = 0
        expect { client.dcerpc_request(request_stub) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when requiring privacy' do
      let(:auth_level) { RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY }
      let(:auth_type) { RubySMB::Dcerpc::RPC_C_AUTHN_WINNT }
      before :example do
        allow(client).to receive(:set_integrity_privacy)
        allow(client).to receive(:handle_integrity_privacy)
      end

      it 'sets integrity and privacy' do
        client.dcerpc_request(request_stub, auth_level: auth_level, auth_type: auth_type)
        expect(client).to have_received(:set_integrity_privacy).with(dcerpc_req, auth_level: auth_level, auth_type: auth_type)
      end

      it 'processes the integrity and privacy information from the response' do
        client.dcerpc_request(request_stub, auth_level: auth_level, auth_type: auth_type)
        expect(client).to have_received(:handle_integrity_privacy).with(dcerpc_res, auth_level: auth_level, auth_type: auth_type)
      end
    end

    context 'with a fragmented response' do
      let(:nb_of_fragments) { 3 }
      before :example do
        dcerpc_res.pdu_header.pfc_flags.last_frag = 0
        count = 0
        allow(client).to receive(:recv_struct) do
          count += 1
          dcerpc_res.pdu_header.pfc_flags.last_frag = 1 if count == nb_of_fragments
          dcerpc_res
        end
      end

      it 'receives the correct number of fragments' do
        client.dcerpc_request(request_stub)
        expect(client).to have_received(:recv_struct).exactly(nb_of_fragments).times.with(RubySMB::Dcerpc::Response)
      end

      it 'returns the correct stub' do
        expect(client.dcerpc_request(request_stub)).to eq(response_stub.to_binary_s * nb_of_fragments)
      end

      context 'when requiring privacy' do
        let(:auth_level) { RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY }
        let(:auth_type) { RubySMB::Dcerpc::RPC_C_AUTHN_WINNT }
        before :example do
          allow(client).to receive(:set_integrity_privacy)
          allow(client).to receive(:handle_integrity_privacy)
        end

        it 'processes the integrity and privacy information for each fragment' do
          client.dcerpc_request(request_stub, auth_level: auth_level, auth_type: auth_type)
          expect(client).to have_received(:recv_struct).exactly(nb_of_fragments).times.with(RubySMB::Dcerpc::Response)
          expect(client).to have_received(:handle_integrity_privacy).exactly(nb_of_fragments).times.with(dcerpc_res, auth_level: auth_level, auth_type: auth_type)
        end
      end
    end
  end

  describe '#send_packet' do
    let(:packet) { double('Packet') }
    let(:data) { 'My data to be sent' }
    let(:sock) { double('Socket') }
    before :example do
      client.tcp_socket = sock
      allow(packet).to receive(:to_binary_s).and_return(data)
      allow(sock).to receive(:write).and_return(data.size)
    end

    it 'sends the correct data' do
      client.send_packet(packet)
      expect(sock).to have_received(:write).with(data)
    end

    context 'when sending multiple chunks of data' do
      it 'sends the correct chunks of data' do
        chunk_size = 6
        allow(sock).to receive(:write).and_return(chunk_size)
        data_sent = data.dup
        client.send_packet(packet)
        loop do
          break if data_sent.empty?
          expect(sock).to have_received(:write).with(data_sent)
          data_sent = data_sent[chunk_size..-1]
        end
      end
    end

    context 'when an error occurs with the socket' do
      it 'raises a CommunicationError' do
        allow(sock).to receive(:write).and_raise (Errno::EPIPE)
        expect { client.send_packet(packet) }.to raise_error(RubySMB::Dcerpc::Error::CommunicationError)
      end
    end
  end

  describe '#recv_struct' do
    let(:socket) { double('Socket') }
    let(:struct) { RubySMB::Dcerpc::Request }
    let(:response) { RubySMB::Dcerpc::Response.new(pdu_header: { ptype: struct::PTYPE}) }
    before :example do
      client.tcp_socket = socket
      allow(socket).to receive(:closed?).and_return false
      allow(IO).to receive(:select).and_return [[client.tcp_socket], [], []]
      allow(struct).to receive(:read).and_return(response)
    end

    it 'reads the socket' do
      client.recv_struct(struct)
      expect(struct).to have_received(:read).with(socket)
    end

    context 'when the socket is already closed' do
      it 'raises a CommunicationError' do
        allow(socket).to receive(:closed?).and_return true
        expect { client.recv_struct(struct) }.to raise_error(RubySMB::Dcerpc::Error::CommunicationError)
      end
    end

    context 'when the read timeout expires' do
      it 'raises a CommunicationError' do
        allow(IO).to receive(:select).and_return nil
        expect { client.recv_struct(struct) }.to raise_error(RubySMB::Dcerpc::Error::CommunicationError)
      end
    end

    context 'when an error occurs when reading the socket' do
      it 'raises an InvalidPacket' do
        allow(struct).to receive(:read).and_raise(IOError)
        expect { client.recv_struct(struct) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when response has a wrong ptype' do
      it 'raises an InvalidPacket' do
        response.pdu_header.ptype = struct::PTYPE + 1
        expect { client.recv_struct(struct) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the read timeout expires' do
      it 'raises a CommunicationError' do
        allow(struct).to receive(:read).and_raise (Errno::EPIPE)
        expect { client.recv_struct(struct) }.to raise_error(RubySMB::Dcerpc::Error::CommunicationError)
      end
    end
  end

  describe '#handle_integrity_privacy' do
    let(:stub) { 'Encrypted Stub' }
    let(:dcerpc_res) do
      RubySMB::Dcerpc::Response.new(
        stub: stub,
        auth_value: signature
      )
    end
    let(:auth_level) { RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY }
    let(:auth_type) { RubySMB::Dcerpc::RPC_C_AUTHN_WINNT }
    let(:session) { double('NTLM Session') }
    let(:decrypted_stub) { 'Decrypted Stub'.b }
    let(:auth_pad) { "\x00" * dcerpc_res.sec_trailer.auth_pad_length.to_i }
    let(:signature) { 'Signature'.b }
    before :example do
      allow(auth_client.ntlm_client).to receive(:session).and_return(session)
      # Make sure the encrypted stub includes the correct pad to make sure sec_trailer is 16-bytes aligned
      allow(session).to receive(:unseal_message).and_return(decrypted_stub + auth_pad)
      allow(session).to receive(:verify_signature).and_return true
    end

    it 'verifies the signature' do
      auth_client.handle_integrity_privacy(dcerpc_res, auth_level: auth_level, auth_type: auth_type)
      data_to_check = dcerpc_res.to_binary_s[0..-(dcerpc_res.pdu_header.auth_length + 1)]
      expect(session).to have_received(:verify_signature).with(signature, data_to_check)
    end

    context 'without NTLM EXTENDED_SECURITY flag' do
      it 'verifies the signature against the correct data' do
        flags = auth_client.ntlm_client.flags ^ RubySMB::NTLM::NEGOTIATE_FLAGS[:EXTENDED_SECURITY]
        allow(auth_client.ntlm_client).to receive(:flags).and_return(flags)
        auth_client.handle_integrity_privacy(dcerpc_res, auth_level: auth_level, auth_type: auth_type)
        data_to_check = dcerpc_res.stub.to_binary_s
        expect(session).to have_received(:verify_signature).with(signature, data_to_check)
      end
    end

    context 'when raise_signature_error is set and the signature is wrong' do
      it 'raises an InvalidPacket exception' do
        allow(session).to receive(:verify_signature).and_return false
        expect {
          auth_client.handle_integrity_privacy(
            dcerpc_res,
            auth_level: auth_level,
            auth_type: auth_type,
            raise_signature_error: true
          )
        }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    it 'decrypts the stub' do
      encrypted_stub = dcerpc_res.stub.to_binary_s + dcerpc_res.auth_pad.to_binary_s
      auth_client.handle_integrity_privacy(dcerpc_res, auth_level: auth_level, auth_type: auth_type)
      expect(dcerpc_res.stub).to eq(decrypted_stub)
      expect(session).to have_received(:unseal_message).with(encrypted_stub)
    end

    context 'without RPC_C_AUTHN_LEVEL_PKT_PRIVACY auth_level' do
      it 'does not encrypt the stub' do
        plain_stub = dcerpc_res.stub.to_binary_s
        auth_client.handle_integrity_privacy(dcerpc_res, auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, auth_type: auth_type)
        expect(dcerpc_res.stub).to eq(plain_stub)
        expect(session).to_not have_received(:unseal_message)
      end
    end

    context 'with an unsupported auth_level' do
      it 'raises an Argument exception' do
        expect { auth_client.handle_integrity_privacy(dcerpc_res, auth_level: auth_level, auth_type: 88) }.to raise_error(ArgumentError)
      end
    end
  end
end

