require 'spec_helper'

RSpec.describe RubySMB::Client do
  let(:sock) { double('Socket', peeraddr: '192.168.1.5') }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(sock) }
  let(:username) { 'msfadmin' }
  let(:password) { 'msfpasswd' }
  subject(:client) { described_class.new(dispatcher, username: username, password: password) }
  let(:smb1_client) { described_class.new(dispatcher, smb2: false, smb3: false, username: username, password: password) }
  let(:smb2_client) { described_class.new(dispatcher, smb1: false, smb3: false, username: username, password: password) }
  let(:smb3_client) { described_class.new(dispatcher, smb1: false, smb2: false, username: username, password: password) }
  let(:empty_packet) { RubySMB::SMB1::Packet::EmptyPacket.new }
  let(:error_packet) { RubySMB::SMB2::Packet::ErrorPacket.new }

  it { is_expected.to respond_to :dispatcher }
  it { is_expected.to respond_to :domain }
  it { is_expected.to respond_to :local_workstation }
  it { is_expected.to respond_to :ntlm_client }
  it { is_expected.to respond_to :password }
  it { is_expected.to respond_to :peer_native_os }
  it { is_expected.to respond_to :peer_native_lm }
  it { is_expected.to respond_to :primary_domain }
  it { is_expected.to respond_to :default_name }
  it { is_expected.to respond_to :default_domain }
  it { is_expected.to respond_to :dns_host_name }
  it { is_expected.to respond_to :dns_domain_name }
  it { is_expected.to respond_to :dns_tree_name }
  it { is_expected.to respond_to :os_version }
  it { is_expected.to respond_to :dialect }
  it { is_expected.to respond_to :sequence_counter }
  it { is_expected.to respond_to :session_id }
  it { is_expected.to respond_to :signing_required }
  it { is_expected.to respond_to :smb1 }
  it { is_expected.to respond_to :smb2 }
  it { is_expected.to respond_to :smb3 }
  it { is_expected.to respond_to :smb2_message_id }
  it { is_expected.to respond_to :username }
  it { is_expected.to respond_to :user_id }
  it { is_expected.to respond_to :max_buffer_size }
  it { is_expected.to respond_to :server_max_buffer_size }
  it { is_expected.to respond_to :server_max_write_size }
  it { is_expected.to respond_to :server_max_read_size }
  it { is_expected.to respond_to :server_max_transact_size }
  it { is_expected.to respond_to :preauth_integrity_hash_algorithm }
  it { is_expected.to respond_to :preauth_integrity_hash_value }
  it { is_expected.to respond_to :encryption_algorithm }
  it { is_expected.to respond_to :client_encryption_key }
  it { is_expected.to respond_to :server_encryption_key }
  it { is_expected.to respond_to :encryption_required }
  it { is_expected.to respond_to :server_encryption_algorithms }
  it { is_expected.to respond_to :server_compression_algorithms }
  it { is_expected.to respond_to :negotiated_smb_version }
  it { is_expected.to respond_to :session_key }
  it { is_expected.to respond_to :tree_connects }
  it { is_expected.to respond_to :open_files }
  it { is_expected.to respond_to :use_ntlmv2 }
  it { is_expected.to respond_to :usentlm2_session }
  it { is_expected.to respond_to :send_lm }
  it { is_expected.to respond_to :use_lanman_key }
  it { is_expected.to respond_to :send_ntlm }
  it { is_expected.to respond_to :spnopt }
  it { is_expected.to respond_to :evasion_opts }
  it { is_expected.to respond_to :native_os }
  it { is_expected.to respond_to :native_lm }
  it { is_expected.to respond_to :verify_signature }
  it { is_expected.to respond_to :auth_user }
  it { is_expected.to respond_to :last_file_id }

  describe '#initialize' do
    it 'should raise an ArgumentError without a valid dispatcher' do
      expect { described_class.new(nil) }.to raise_error(ArgumentError)
    end

    it 'defaults to true for SMB1 support' do
      expect(client.smb1).to be true
    end

    it 'defaults to true for SMB2 support' do
      expect(client.smb1).to be true
    end

    it 'accepts an argument to disable smb1 support' do
      expect(smb2_client.smb1).to be false
      expect(smb3_client.smb1).to be false
    end

    it 'accepts an argument to disable smb2 support' do
      expect(smb1_client.smb2).to be false
      expect(smb3_client.smb2).to be false
    end

    it 'accepts an argument to disable smb3 support' do
      expect(smb1_client.smb3).to be false
      expect(smb2_client.smb3).to be false
    end

    it 'raises an exception if SMB1, SMB2 and SMB3 are disabled' do
      expect { described_class.new(dispatcher, smb1: false, smb2: false, smb3: false, username: username, password: password) }.to raise_error(ArgumentError, 'You must enable at least one Protocol')
    end

    it 'sets the username attribute' do
      expect(client.username).to eq username
    end

    it 'sets the password attribute' do
      expect(client.password).to eq password
    end

    it 'sets the encryption_required attribute' do
      client =  described_class.new(dispatcher, username: username, password: password, always_encrypt: true)
      expect(client.encryption_required).to eq true
    end

    it 'creates an NTLM client' do
      expect(client.ntlm_client).to be_a Net::NTLM::Client
    end

    it 'passes the expected arguments when creating the NTLM client' do
      domain = 'SPEC_DOMAIN'
      local_workstation = 'SPEC_WORKSTATION'

      allow(Net::NTLM::Client).to receive(:new) do |username, passwd, opt|
        expect(username).to eq(username)
        expect(password).to eq(password)
        expect(opt[:workstation]).to eq(local_workstation)
        expect(opt[:domain]).to eq(domain)
        flags = Net::NTLM::Client::DEFAULT_FLAGS |
          Net::NTLM::FLAGS[:TARGET_INFO] | 0x02000000
        expect(opt[:flags]).to eq(flags)
      end

      described_class.new(
        dispatcher,
        username: username,
        password: password,
        domain: domain,
        local_workstation: local_workstation
      )
    end

    it 'sets the max_buffer_size to MAX_BUFFER_SIZE' do
      expect(client.max_buffer_size).to eq RubySMB::Client::MAX_BUFFER_SIZE
    end
  end

  describe '#echo' do
    let(:response) { double('Echo Response') }
    before :example do
      allow(response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_SUCCESS)
    end

    context 'with SMB1' do
      it 'calls #smb1_echo with the expected arguments' do
        allow(smb1_client).to receive(:smb1_echo).and_return(response)
        count = 3
        data  = 'testing...'
        smb1_client.echo(count: count, data: data)
        expect(smb1_client).to have_received(:smb1_echo).with(count: count, data: data)
      end
    end

    context 'with SMB2' do
      it 'calls #smb2_echo without arguments' do
        allow(smb2_client).to receive(:smb2_echo).and_return(response)
        smb2_client.echo
        expect(smb2_client).to have_received(:smb2_echo)
      end
    end

    context 'with SMB3' do
      it 'calls #smb2_echo without arguments' do
        allow(smb3_client).to receive(:smb2_echo).and_return(response)
        smb3_client.echo
        expect(smb3_client).to have_received(:smb2_echo)
      end
    end

    it 'returns the expected status code' do
      allow(smb2_client).to receive(:smb2_echo).and_return(response)
      expect(smb2_client.echo).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
    end
  end

  describe '#send_recv' do
    let(:smb1_request) { RubySMB::SMB1::Packet::TreeConnectRequest.new }
    let(:smb2_request) { RubySMB::SMB2::Packet::TreeConnectRequest.new }

    before(:each) do
      allow(client).to receive(:is_status_pending?).and_return(false)
      allow(dispatcher).to receive(:send_packet).and_return(nil)
      allow(dispatcher).to receive(:recv_packet).and_return('A')
    end

    it 'checks the packet version' do
      expect(smb1_request).to receive(:packet_smb_version).and_call_original
      client.send_recv(smb1_request)
    end

    context 'when signing' do
      it 'calls #smb1_sign if it is an SMB1 packet' do
        expect(client).to receive(:smb1_sign).with(smb1_request).and_call_original
        client.send_recv(smb1_request)
      end

      context 'with an SMB2 packet' do
        it 'does not sign a SessionSetupRequest packet' do
          expect(smb2_client).to_not receive(:smb2_sign)
          expect(smb2_client).to_not receive(:smb3_sign)
          client.send_recv(RubySMB::SMB2::Packet::SessionSetupRequest.new)
        end

        it 'calls #smb2_sign if it is an SMB2 client' do
          allow(smb2_client).to receive(:is_status_pending?).and_return(false)
          expect(smb2_client).to receive(:smb2_sign).with(smb2_request).and_call_original
          smb2_client.send_recv(smb2_request)
        end

        it 'calls #smb3_sign if it is an SMB3 client' do
          allow(smb3_client).to receive(:is_status_pending?).and_return(false)
          expect(smb3_client).to receive(:smb3_sign).with(smb2_request).and_call_original
          smb3_client.send_recv(smb2_request)
        end
      end
    end

    it 'sends the expected packet and gets the response' do
      expect(dispatcher).to receive(:send_packet).with(smb1_request)
      expect(dispatcher).to receive(:recv_packet)
      client.send_recv(smb1_request)
    end

    context 'with SMB1' do
      it 'does not check if it is a STATUS_PENDING response' do
        expect(smb1_client).to_not receive(:is_status_pending?)
        smb1_client.send_recv(smb1_request)
      end
    end

    context 'with SMB2' do
      context 'when receiving a STATUS_PENDING response' do
        it 'waits 1 second and reads/decrypts again' do
          allow(smb2_client).to receive(:is_status_pending?).and_return(true, false)
          expect(smb2_client).to receive(:sleep).with(1)
          expect(dispatcher).to receive(:recv_packet).twice
          smb2_client.send_recv(smb2_request)
        end
      end
    end

    context 'with SMB3 and encryption' do
      before :example do
        smb3_client.dialect = '0x0300'
        allow(smb3_client).to receive(:is_status_pending?).and_return(false)
      end

      context 'with a SessionSetupRequest' do
        it 'does not encrypt/decrypt' do
          request = RubySMB::SMB2::Packet::SessionSetupRequest.new
          expect(smb3_client).to_not receive(:send_encrypt).with(request)
          expect(smb3_client).to_not receive(:recv_encrypt)
          expect(dispatcher).to receive(:send_packet).with(request)
          expect(dispatcher).to receive(:recv_packet)
          smb3_client.send_recv(request)
        end
      end

      context 'with a NegotiateRequest' do
        it 'does not encrypt/decrypt' do
          request = RubySMB::SMB2::Packet::NegotiateRequest.new
          expect(smb3_client).to_not receive(:send_encrypt).with(request)
          expect(smb3_client).to_not receive(:recv_encrypt)
          expect(dispatcher).to receive(:send_packet).with(request)
          expect(dispatcher).to receive(:recv_packet)
          smb3_client.send_recv(request)
        end
      end

      it 'encrypts and decrypts' do
        expect(smb3_client).to receive(:send_encrypt).with(smb2_request)
        expect(smb3_client).to receive(:recv_encrypt)
        smb3_client.send_recv(smb2_request)
      end

      context 'when receiving a STATUS_PENDING response' do
        it 'waits 1 second and reads/decrypts again' do
          allow(smb3_client).to receive(:is_status_pending?).and_return(true, false)
          expect(smb3_client).to receive(:sleep).with(1)
          expect(smb3_client).to receive(:send_encrypt).with(smb2_request)
          expect(smb3_client).to receive(:recv_encrypt).twice
          smb3_client.send_recv(smb2_request)
        end
      end
    end
  end

  describe '#is_status_pending?' do
    let(:response) {
      res = RubySMB::SMB2::Packet::SessionSetupRequest.new
      res.smb2_header.nt_status= WindowsError::NTStatus::STATUS_PENDING.value
      res.smb2_header.flags.async_command = 1
      res
    }

    it 'returns true when the response has a STATUS_PENDING status code and the async_command flag set' do
      expect(client.is_status_pending?(response.to_binary_s)).to be true
    end

    it 'returns false when the response has a STATUS_PENDING status code and the async_command flag not set' do
      response.smb2_header.flags.async_command = 0
      expect(client.is_status_pending?(response.to_binary_s)).to be false
    end

    it 'returns false when the response has no STATUS_PENDING status code but the async_command flag set' do
      response.smb2_header.nt_status= WindowsError::NTStatus::STATUS_SUCCESS.value
      expect(client.is_status_pending?(response.to_binary_s)).to be false
    end
  end

  describe '#send_encrypt' do
    let(:packet) { RubySMB::SMB2::Packet::SessionSetupRequest.new }
    before :example do
      allow(dispatcher).to receive(:send_packet)
      client.dialect = '0x0300'
    end

    it 'creates a Transform request' do
      expect(client).to receive(:smb3_encrypt).with(packet.to_binary_s)
      client.send_encrypt(packet)
    end

    it 'raises an EncryptionError exception if an error occurs while encrypting' do
      allow(client).to receive(:smb3_encrypt).and_raise(RubySMB::Error::RubySMBError.new('Error'))
      expect { client.send_encrypt(packet) }.to raise_error(
        RubySMB::Error::EncryptionError,
        "Error while encrypting #{packet.class.name} packet (SMB 0x0300): Error"
      )
    end

    it 'sends the encrypted packet' do
      encrypted_packet = double('Encrypted packet')
      allow(client).to receive(:smb3_encrypt).and_return(encrypted_packet)
      client.send_encrypt(packet)
      expect(dispatcher).to have_received(:send_packet).with(encrypted_packet)
    end
  end

  describe '#recv_encrypt' do
    let(:packet) { RubySMB::SMB2::Packet::SessionSetupRequest.new }
    before :example do
      allow(dispatcher).to receive(:recv_packet).and_return(packet.to_binary_s)
      client.dialect = '0x0300'
      allow(client).to receive(:smb3_decrypt)
    end

    it 'reads the response packet' do
      client.recv_encrypt
      expect(dispatcher).to have_received(:recv_packet)
    end

    it 'parses the response as a Transform response packet' do
      expect(RubySMB::SMB2::Packet::TransformHeader).to receive(:read).with(packet.to_binary_s)
      client.recv_encrypt
    end

    it 'raises an InvalidPacket exception if an error occurs while parsing the response' do
      allow(RubySMB::SMB2::Packet::TransformHeader).to receive(:read).and_raise(IOError)
      expect { client.recv_encrypt}.to raise_error(RubySMB::Error::InvalidPacket, 'Not a SMB2 TransformHeader packet')
    end

    it 'decrypts the Transform response packet' do
      transform = double('Transform header packet')
      allow(RubySMB::SMB2::Packet::TransformHeader).to receive(:read).and_return(transform)
      client.recv_encrypt
      expect(client).to have_received(:smb3_decrypt).with(transform)
    end

    it 'raises an EncryptionError exception if an error occurs while decrypting' do
      allow(client).to receive(:smb3_decrypt).and_raise(RubySMB::Error::RubySMBError )
      expect { client.recv_encrypt}.to raise_error(
        RubySMB::Error::EncryptionError,
        "Error while decrypting RubySMB::SMB2::Packet::TransformHeader packet (SMB 0x0300}): RubySMB::Error::RubySMBError"
      )
    end
  end

  describe '#login' do
    before(:each) do
      allow(client).to receive(:negotiate)
      allow(client).to receive(:authenticate)
    end

    it 'defaults username to what was in the initializer' do
      expect { client.login }.to_not change(client, :username)
    end

    it 'overrides username if it is passed as a parameter' do
      expect { client.login(username: 'test') }.to change(client, :username).to('test')
    end

    it 'defaults password to what was in the initializer' do
      expect { client.login }.to_not change(client, :password)
    end

    it 'overrides password if it is passed as a parameter' do
      expect { client.login(password: 'test') }.to change(client, :password).to('test')
    end

    it 'defaults domain to what was in the initializer' do
      expect { client.login }.to_not change(client, :domain)
    end

    it 'overrides domain if it is passed as a parameter' do
      expect { client.login(domain: 'test') }.to change(client, :domain).to('test')
    end

    it 'defaults local_workstation to what was in the initializer' do
      expect { client.login }.to_not change(client, :local_workstation)
    end

    it 'overrides local_workstation if it is passed as a parameter' do
      expect { client.login(local_workstation: 'test') }.to change(client, :local_workstation).to('test')
    end

    it 'initialises a new NTLM Client' do
      expect { client.login }.to change(client, :ntlm_client)
    end

    it 'calls negotiate after the setup' do
      expect(client).to receive(:negotiate)
      client.login
    end

    it 'calls authenticate after negotiate' do
      expect(client).to receive(:authenticate)
      client.login
    end
  end

  describe '#logoff!' do
    context 'with SMB1' do
      let(:raw_response) { double('Raw response') }
      let(:logoff_response) {
        RubySMB::SMB1::Packet::LogoffResponse.new(smb_header: {:command => RubySMB::SMB1::Commands::SMB_COM_LOGOFF} )
      }
      before :example do
        allow(smb1_client).to receive(:send_recv).and_return(raw_response)
        allow(RubySMB::SMB1::Packet::LogoffResponse).to receive(:read).and_return(logoff_response)
        allow(smb1_client).to receive(:wipe_state!)
      end

      it 'creates a LogoffRequest packet' do
        expect(RubySMB::SMB1::Packet::LogoffRequest).to receive(:new).and_call_original
        smb1_client.logoff!
      end

      it 'calls #send_recv' do
        expect(smb1_client).to receive(:send_recv)
        smb1_client.logoff!
      end

      it 'reads the raw response as a LogoffResponse packet' do
        expect(RubySMB::SMB1::Packet::LogoffResponse).to receive(:read).with(raw_response)
        smb1_client.logoff!
      end

      it 'raise an InvalidPacket exception when the response is an empty packet' do
        allow(RubySMB::SMB1::Packet::LogoffResponse).to receive(:read).and_return(RubySMB::SMB1::Packet::EmptyPacket.new)
        expect {smb1_client.logoff!}.to raise_error(RubySMB::Error::InvalidPacket)
      end

      it 'raise an InvalidPacket exception when the response is not valid' do
        allow(logoff_response).to receive(:valid?).and_return(false)
        expect {smb1_client.logoff!}.to raise_error(RubySMB::Error::InvalidPacket)
      end

      it 'calls #wipe_state!' do
        expect(smb1_client).to receive(:wipe_state!)
        smb1_client.logoff!
      end

      it 'returns the expected status code' do
        logoff_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_PENDING.value
        allow(RubySMB::SMB1::Packet::LogoffResponse).to receive(:read).and_return(logoff_response)
        expect(smb1_client.logoff!).to eq(WindowsError::NTStatus::STATUS_PENDING)
      end
    end

    context 'with SMB2' do
      let(:raw_response) { double('Raw response') }
      let(:logoff_response) {
        RubySMB::SMB2::Packet::LogoffResponse.new(smb_header: {:command => RubySMB::SMB2::Commands::LOGOFF} )
      }
      before :example do
        allow(smb2_client).to receive(:send_recv).and_return(raw_response)
        allow(RubySMB::SMB2::Packet::LogoffResponse).to receive(:read).and_return(logoff_response)
        allow(smb2_client).to receive(:wipe_state!)
      end

      it 'creates a LogoffRequest packet' do
        expect(RubySMB::SMB2::Packet::LogoffRequest).to receive(:new).and_call_original
        smb2_client.logoff!
      end

      it 'calls #send_recv' do
        expect(smb2_client).to receive(:send_recv)
        smb2_client.logoff!
      end

      it 'reads the raw response as a LogoffResponse packet' do
        expect(RubySMB::SMB2::Packet::LogoffResponse).to receive(:read).with(raw_response)
        smb2_client.logoff!
      end

      it 'raise an InvalidPacket exception when the response is an error packet' do
        allow(RubySMB::SMB2::Packet::LogoffResponse).to receive(:read).and_return(RubySMB::SMB2::Packet::ErrorPacket.new)
        expect {smb2_client.logoff!}.to raise_error(RubySMB::Error::InvalidPacket)
      end

      it 'raise an InvalidPacket exception when the response is not a LOGOFF command' do
        logoff_response.smb2_header.command = RubySMB::SMB2::Commands::ECHO
        allow(RubySMB::SMB2::Packet::LogoffResponse).to receive(:read).and_return(logoff_response)
        expect {smb2_client.logoff!}.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end

    context 'with SMB3' do
      let(:raw_response) { double('Raw response') }
      let(:logoff_response) {
        RubySMB::SMB2::Packet::LogoffResponse.new(smb_header: {:command => RubySMB::SMB2::Commands::LOGOFF} )
      }
      before :example do
        allow(smb3_client).to receive(:send_recv).and_return(raw_response)
        allow(RubySMB::SMB2::Packet::LogoffResponse).to receive(:read).and_return(logoff_response)
        allow(smb3_client).to receive(:wipe_state!)
      end

      it 'creates a LogoffRequest packet' do
        expect(RubySMB::SMB2::Packet::LogoffRequest).to receive(:new).and_call_original
        smb3_client.logoff!
      end

      it 'calls #send_recv' do
        expect(smb3_client).to receive(:send_recv)
        smb3_client.logoff!
      end

      it 'reads the raw response as a LogoffResponse packet' do
        expect(RubySMB::SMB2::Packet::LogoffResponse).to receive(:read).with(raw_response)
        smb3_client.logoff!
      end

      it 'raise an InvalidPacket exception when the response is an error packet' do
        allow(RubySMB::SMB2::Packet::LogoffResponse).to receive(:read).and_return(RubySMB::SMB2::Packet::ErrorPacket.new)
        expect {smb3_client.logoff!}.to raise_error(RubySMB::Error::InvalidPacket)
      end

      it 'raise an InvalidPacket exception when the response is not a LOGOFF command' do
        logoff_response.smb2_header.command = RubySMB::SMB2::Commands::ECHO
        allow(RubySMB::SMB2::Packet::LogoffResponse).to receive(:read).and_return(logoff_response)
        expect {smb3_client.logoff!}.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end
  end

  context 'NetBIOS Session Service' do
    describe '#session_request' do
      let(:session_header)  { RubySMB::Nbss::SessionHeader.new }
      let(:session_request) { RubySMB::Nbss::SessionRequest.new }

      before :example do
        allow(RubySMB::Nbss::SessionRequest).to receive(:new).and_return(session_request)
        allow(dispatcher).to receive(:send_packet)
        allow(dispatcher).to receive(:recv_packet).and_return(session_header.to_binary_s)
      end

      it 'calls #session_request_packet' do
        called_name = 'SPECNAME'
        expect(client).to receive(:session_request_packet).with(called_name)
        client.session_request(called_name)
      end

      it 'sends the SessionRequest packet without adding additional NetBIOS Session Header' do
        expect(dispatcher).to receive(:send_packet).with(session_request, nbss_header: false)
        client.session_request
      end

      it 'reads the full response packet, including the NetBIOS Session Header' do
        expect(dispatcher).to receive(:recv_packet).with(full_response: true).and_return(session_header.to_binary_s)
        client.session_request
      end

      it 'parses the response with SessionHeader packet structure' do
        expect(RubySMB::Nbss::SessionHeader).to receive(:read).with(session_header.to_binary_s).and_return(session_header)
        client.session_request
      end

      it 'returns true when it is a POSITIVE_SESSION_RESPONSE' do
        session_header.session_packet_type = RubySMB::Nbss::POSITIVE_SESSION_RESPONSE
        expect(client.session_request).to be true
      end

      it 'raises an exception when it is a NEGATIVE_SESSION_RESPONSE' do
        negative_session_response = RubySMB::Nbss::NegativeSessionResponse.new
        negative_session_response.session_header.session_packet_type = RubySMB::Nbss::NEGATIVE_SESSION_RESPONSE
        negative_session_response.error_code = 0x80
        allow(dispatcher).to receive(:recv_packet).and_return(negative_session_response.to_binary_s)
        expect { client.session_request }.to raise_error(RubySMB::Error::NetBiosSessionService)
      end

      it 'raises an InvalidPacket exception when an error occurs while reading' do
        allow(RubySMB::Nbss::SessionHeader).to receive(:read).and_raise(IOError)
        expect { client.session_request }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end

    describe '#session_request_packet' do
      it 'creates a SessionRequest packet' do
        session_request = RubySMB::Nbss::SessionRequest.new
        expect(RubySMB::Nbss::SessionRequest).to receive(:new).and_return(session_request)
        client.session_request_packet
      end

      it 'sets the expected fields of the SessionRequest packet' do
        name         = 'NBNAMESPEC'
        called_name  = 'NBNAMESPEC      '
        calling_name = "               \x00"

        session_packet = client.session_request_packet(name)
        expect(session_packet).to be_a(RubySMB::Nbss::SessionRequest)
        expect(session_packet.session_header.session_packet_type).to eq RubySMB::Nbss::SESSION_REQUEST
        expect(session_packet.called_name).to eq called_name
        expect(session_packet.calling_name).to eq calling_name
        expect(session_packet.session_header.packet_length).to eq(
          session_packet.called_name.to_binary_s.size + session_packet.calling_name.to_binary_s.size
        )
      end

      it 'converts the called name to upperase' do
        name = 'myname'
        session_packet = client.session_request_packet(name)
        expect(session_packet.called_name).to eq("#{name.upcase.ljust(15)}\x20")
      end

      it 'returns a session packet with *SMBSERVER by default' do
        expect(client.session_request_packet.called_name).to eq('*SMBSERVER      ')
      end
    end
  end

  context 'Protocol Negotiation' do
    let(:random_junk) { 'fgrgrwgawrtw4t4tg4gahgn' }
    let(:smb1_capabilities) {
      { level_2_oplocks: 1,
        nt_status: 1,
        rpc_remote_apis: 1,
        nt_smbs: 1,
        large_files: 1,
        unicode: 1,
        mpx_mode: 0,
        raw_mode: 0,
        large_writex: 1,
        large_readx: 1,
        info_level_passthru: 1,
        dfs: 0,
        reserved1: 0,
        bulk_transfer: 0,
        nt_find: 1,
        lock_and_read: 1,
        unix: 0,
        reserved2: 0,
        lwio: 1,
        extended_security: 1,
        reserved3: 0,
        dynamic_reauth: 0,
        reserved4: 0,
        compressed_data: 0,
        reserved5: 0 }
    }
    let(:smb1_extended_response) {
      packet = RubySMB::SMB1::Packet::NegotiateResponseExtended.new
      packet.parameter_block.capabilities = smb1_capabilities
      packet
    }
    let(:smb1_extended_response_raw) {
      smb1_extended_response.to_binary_s
    }

    let(:smb2_response) { RubySMB::SMB2::Packet::NegotiateResponse.new(dialect_revision: 0x200) }
    let(:smb3_response) { RubySMB::SMB2::Packet::NegotiateResponse.new(dialect_revision: 0x300) }

    describe '#smb1_negotiate_request' do
      it 'returns an SMB1 Negotiate Request packet' do
        expect(client.smb1_negotiate_request).to be_a(RubySMB::SMB1::Packet::NegotiateRequest)
      end

      it 'sets the default SMB1 Dialect' do
        expect(client.smb1_negotiate_request.dialects).to include(
          buffer_format: 2,
          dialect_string: RubySMB::Client::SMB1_DIALECT_SMB1_DEFAULT
        )
      end

      it 'sets the SMB2.02 dialect if SMB2 support is enabled' do
        expect(client.smb1_negotiate_request.dialects).to include(
          buffer_format: 2,
          dialect_string: RubySMB::Client::SMB1_DIALECT_SMB2_DEFAULT
        )
      end

      it 'excludes the SMB2.02 Dialect if SMB2 support is disabled' do
        expect(smb1_client.smb1_negotiate_request.dialects).to_not include(
          buffer_format: 2,
          dialect_string: RubySMB::Client::SMB1_DIALECT_SMB2_DEFAULT
        )
      end

      it 'excludes the default SMB1 Dialect if SMB1 support is disabled' do
        expect(smb2_client.smb1_negotiate_request.dialects).to_not include(
          buffer_format: 2,
          dialect_string: RubySMB::Client::SMB1_DIALECT_SMB1_DEFAULT
        )
      end

      it 'sets the SMB wildcard dialect if SMB2 support is enabled' do
        expect(client.smb1_negotiate_request.dialects).to include(
          buffer_format: 2,
          dialect_string: RubySMB::Client::SMB1_DIALECT_SMB2_WILDCARD
        )
      end

      it 'sets the SMB wildcard dialect if SMB3 support is enabled' do
        expect(smb3_client.smb1_negotiate_request.dialects).to include(
          buffer_format: 2,
          dialect_string: RubySMB::Client::SMB1_DIALECT_SMB2_WILDCARD
        )
      end

      it 'excludes the SMB wildcard dialect if both SMB2 and SMB3 supports are disabled' do
        expect(smb1_client.smb1_negotiate_request.dialects).to_not include(
          buffer_format: 2,
          dialect_string: RubySMB::Client::SMB1_DIALECT_SMB2_WILDCARD
        )
      end
    end

    describe '#smb2_3_negotiate_request' do
      it 'return an SMB2 Negotiate Request packet' do
        expect(client.smb2_3_negotiate_request).to be_a(RubySMB::SMB2::Packet::NegotiateRequest)
      end

      it 'sets the default SMB2 Dialect if SMB2 support is enabled' do
        expect(client.smb2_3_negotiate_request.dialects).to include(*RubySMB::Client::SMB2_DIALECT_DEFAULT)
      end

      it 'does not set the default SMB2 Dialect if SMB2 support is disabled' do
        expect(smb3_client.smb2_3_negotiate_request.dialects).to_not include(*RubySMB::Client::SMB2_DIALECT_DEFAULT)
      end

      it 'sets the Message ID to 0' do
        expect(client.smb2_3_negotiate_request.smb2_header.message_id).to eq 0
      end

      it 'adds SMB3 dialects if if SMB3 support is enabled' do
        expect(client.smb2_3_negotiate_request.dialects).to include(*RubySMB::Client::SMB3_DIALECT_DEFAULT)
      end

      it 'does not set the default SMB3 Dialect if SMB3 support is disabled' do
        expect(smb2_client.smb2_3_negotiate_request.dialects).to_not include(*RubySMB::Client::SMB3_DIALECT_DEFAULT)
      end
    end

    describe '#add_smb3_to_negotiate_request' do
      let(:negotiate_request) { RubySMB::SMB2::Packet::NegotiateRequest.new }

      it 'adds the default SMB3 dialects' do
        expect(client.add_smb3_to_negotiate_request(negotiate_request).dialects).to include(
          *RubySMB::Client::SMB3_DIALECT_DEFAULT
        )
      end

      it 'sets encryption capability flag' do
        expect(client.add_smb3_to_negotiate_request(negotiate_request).capabilities.encryption).to eq(1)
      end

      context 'when the negotiate packet includes the 0x0311 dialect' do
        before :example do
          client.add_smb3_to_negotiate_request(negotiate_request, [0x0311])
        end

        it 'adds 3 Negotiate Contexts' do
          expect(negotiate_request.negotiate_context_info.negotiate_context_count).to eq(3)
        end

        it 'adds a Preauth Integrity Negotiate Context with the expected hash algorithms' do
          nc = negotiate_request.negotiate_context_list.select do |n|
              n.context_type == RubySMB::SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES
          end
          expect(nc.length).to eq(1)
          expect(nc.first.data.hash_algorithms).to eq([RubySMB::SMB2::PreauthIntegrityCapabilities::SHA_512])
        end

        it 'adds Encryption Negotiate Contexts with the expected encryption algorithms' do
          nc = negotiate_request.negotiate_context_list.select do |n|
              n.context_type == RubySMB::SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES
          end
          expect(nc.length).to eq(1)
          expect(nc.first.data.ciphers).to eq(
            [
              RubySMB::SMB2::EncryptionCapabilities::AES_128_CCM,
              RubySMB::SMB2::EncryptionCapabilities::AES_128_GCM
            ]
          )
        end

        it 'adds Compression Negotiate Contexts with the expected compression algorithms' do
          nc = negotiate_request.negotiate_context_list.select do |n|
              n.context_type == RubySMB::SMB2::NegotiateContext::SMB2_COMPRESSION_CAPABILITIES
          end
          expect(nc.length).to eq(1)
          expect(nc.first.data.compression_algorithms).to eq(
            [
              RubySMB::SMB2::CompressionCapabilities::LZNT1,
              RubySMB::SMB2::CompressionCapabilities::LZ77,
              RubySMB::SMB2::CompressionCapabilities::LZ77_Huffman,
              RubySMB::SMB2::CompressionCapabilities::Pattern_V1
            ]
          )
        end
      end

      context 'when the negotiate packet does not include the 0x0311 dialect' do
        before :example do
          client.add_smb3_to_negotiate_request(negotiate_request, [0x0300, 0x0302])
        end
      end
    end

    describe '#negotiate_request' do
      it 'calls #smb1_negotiate_request if SMB1 is enabled' do
        expect(smb1_client).to receive(:smb1_negotiate_request)
        smb1_client.negotiate_request
      end

      it 'calls #smb1_negotiate_request if both protocols are enabled' do
        expect(client).to receive(:smb1_negotiate_request)
        client.negotiate_request
      end

      it 'calls #smb2_3_negotiate_request if SMB2 is enabled' do
        expect(smb2_client).to receive(:smb2_3_negotiate_request)
        smb2_client.negotiate_request
      end

      it 'calls #smb2_3_negotiate_request if SMB3 is enabled' do
        expect(smb3_client).to receive(:smb2_3_negotiate_request)
        smb3_client.negotiate_request
      end
    end

    describe '#negotiate_response' do
      context 'with only SMB1' do
        it 'returns a properly formed packet' do
          expect(smb1_client.negotiate_response(smb1_extended_response_raw)).to eq smb1_extended_response
        end

        it 'raises an exception if the response is not a SMB packet' do
          expect { smb1_client.negotiate_response(random_junk) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'raises an InvalidPacket error if the response is not a valid response' do
          empty_packet.smb_header.command = RubySMB::SMB2::Commands::NEGOTIATE
          expect { smb1_client.negotiate_response(empty_packet.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'considers the response invalid if it is not an actual Negotiate Response' do
          bogus_response = smb1_extended_response
          bogus_response.smb_header.command = 0xff
          expect { smb1_client.negotiate_response(bogus_response.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'considers the response invalid if Extended Security is not enabled' do
          bogus_response = smb1_extended_response
          bogus_response.parameter_block.capabilities.extended_security = 0
          expect { smb1_client.negotiate_response(bogus_response.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'with only SMB2' do
        it 'returns a properly formed packet' do
          expect(smb2_client.negotiate_response(smb2_response.to_binary_s)).to eq smb2_response
        end

        it 'raises an exception if the Response is invalid' do
          expect { smb2_client.negotiate_response(random_junk) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'considers the response invalid if it is not an actual Negotiate Response' do
          bogus_response = smb2_response
          bogus_response.smb2_header.command = RubySMB::SMB2::Commands::ECHO
          expect { smb2_client.negotiate_response(bogus_response.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'with only SMB3' do
        it 'returns a properly formed packet' do
          expect(smb3_client.negotiate_response(smb2_response.to_binary_s)).to eq smb2_response
        end

        it 'raises an exception if the Response is invalid' do
          expect { smb3_client.negotiate_response(random_junk) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'considers the response invalid if it is not an actual Negotiate Response' do
          bogus_response = smb2_response
          bogus_response.smb2_header.command = RubySMB::SMB2::Commands::ECHO
          expect { smb3_client.negotiate_response(bogus_response.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'with SMB1, SMB2 and SMB3 enabled' do
        it 'returns an SMB1 NegotiateResponse if it looks like SMB1' do
          expect(client.negotiate_response(smb1_extended_response_raw)).to eq smb1_extended_response
        end

        it 'returns an SMB2 NegotiateResponse if it looks like SMB2 or SMB3' do
          expect(client.negotiate_response(smb2_response.to_binary_s)).to eq smb2_response
        end
      end
    end

    describe '#parse_negotiate_response' do
      context 'when SMB1 was Negotiated' do
        it 'turns off SMB2 and SMB3 support' do
          client.parse_negotiate_response(smb1_extended_response)
          expect(client.smb2).to be false
          expect(client.smb3).to be false
        end

        it 'sets whether or not signing is required' do
          smb1_extended_response.parameter_block.security_mode.security_signatures_required = 1
          client.parse_negotiate_response(smb1_extended_response)
          expect(client.signing_required).to be true
        end

        it 'sets #dialect to the negotiated dialect' do
          smb1_extended_response.dialects = [
            RubySMB::SMB1::Dialect.new(dialect_string: 'A'),
            RubySMB::SMB1::Dialect.new(dialect_string: 'B'),
            RubySMB::SMB1::Dialect.new(dialect_string: 'C'),
          ]
          smb1_extended_response.parameter_block.dialect_index = 1
          client.parse_negotiate_response(smb1_extended_response)
          expect(client.dialect).to eq 'B'
        end

        it 'returns the string \'SMB1\'' do
          expect(client.parse_negotiate_response(smb1_extended_response)).to eq ('SMB1')
        end

        it 'sets #negotiated_smb_version to 1' do
          client.parse_negotiate_response(smb1_extended_response)
          expect(client.negotiated_smb_version).to eq(1)
        end
      end

      context 'when SMB2 was negotiated' do
        it 'turns off SMB1 and SMB3 support' do
          client.parse_negotiate_response(smb2_response)
          expect(client.smb1).to be false
          expect(client.smb3).to be false
        end

        it 'sets whether or not signing is required' do
          smb2_response.security_mode.signing_required = 1
          client.parse_negotiate_response(smb2_response)
          expect(client.signing_required).to be true
        end

        it 'sets #dialect to the negotiated dialect' do
          smb2_response.dialect_revision = 2
          client.parse_negotiate_response(smb2_response)
          expect(client.dialect).to eq '0x0002'
        end

        it 'returns the string \'SMB2\'' do
          expect(client.parse_negotiate_response(smb2_response)).to eq ('SMB2')
        end
      end

      context 'when SMB3 was negotiated' do
        it 'turns off SMB1 and SMB2 support' do
          client.parse_negotiate_response(smb3_response)
          expect(client.smb1).to be false
          expect(client.smb2).to be false
        end

        it 'sets whether or not signing is required' do
          smb3_response.security_mode.signing_required = 1
          client.parse_negotiate_response(smb3_response)
          expect(client.signing_required).to be true
        end

        it 'sets #dialect to the negotiated dialect' do
          client.parse_negotiate_response(smb3_response)
          expect(client.dialect).to eq '0x0300'
        end

        it 'returns the string \'SMB2\'' do
          expect(client.parse_negotiate_response(smb3_response)).to eq ('SMB3')
        end
      end

      context 'when the response contains the SMB2 wildcard revision number dialect' do
        it 'only turns off SMB1 support' do
          smb2_response = RubySMB::SMB2::Packet::NegotiateResponse.new(dialect_revision: 0x02ff)
          client.parse_negotiate_response(smb2_response)
          expect(client.smb1).to be false
          expect(client.smb2).to be true
          expect(client.smb3).to be true
        end
      end

      context 'when the negotiation failed' do
        context 'with a STATUS_NOT_SUPPORTED status code' do
          before :example do
            error_packet.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NOT_SUPPORTED.value
          end

          it 'raises the expected exception with SMB2' do
            expect { smb2_client.parse_negotiate_response(error_packet) }.to raise_error(
            RubySMB::Error::NegotiationFailure,
            'Unable to negotiate with remote host, SMB2 not supported'
            )
          end

          it 'raises the expected exception with SMB3' do
            expect { smb3_client.parse_negotiate_response(error_packet) }.to raise_error(
            RubySMB::Error::NegotiationFailure,
            'Unable to negotiate with remote host, SMB3 not supported'
            )
          end
        end

        context 'with an unknown status code' do
          it 'raises the expected exception' do
            expect { client.parse_negotiate_response(empty_packet) }.to raise_error(
            RubySMB::Error::NegotiationFailure,
            'Unable to negotiate with remote host'
            )
          end
        end
      end
    end

    describe '#negotiate' do
      let(:request_packet) { client.smb1_negotiate_request }
      before :example do
        allow(client).to receive(:negotiate_request)
        allow(client).to receive(:send_recv)
        allow(client).to receive(:negotiate_response)
        allow(client).to receive(:parse_negotiate_response)
      end

      it 'calls the backing methods' do
        expect(client).to receive(:negotiate_request)
        expect(client).to receive(:send_recv)
        expect(client).to receive(:negotiate_response)
        expect(client).to receive(:parse_negotiate_response)
        client.negotiate
      end

      context 'with SMB1' do
        it 'sets the response-packet #dialects array with the dialects sent in the request' do
          request_packet = client.smb1_negotiate_request
          allow(client).to receive(:negotiate_request).and_return(request_packet)
          allow(client).to receive(:negotiate_response).and_return(smb1_extended_response)
          expect(smb1_extended_response).to receive(:dialects=).with(request_packet.dialects)
          client.negotiate
        end
      end

      ['0x0300', '0x0302'].each do |dialect|
        context "with #{dialect} dialect" do
          before :example do
            client.dialect = dialect
          end

          it 'sets the expected encryption algorithm' do
            client.negotiate
            expect(client.encryption_algorithm).to eq(RubySMB::SMB2::EncryptionCapabilities::ENCRYPTION_ALGORITHM_MAP[RubySMB::SMB2::EncryptionCapabilities::AES_128_CCM])
          end
        end
      end

      context "with 0x0311 dialect" do
        it 'calls #parse_smb3_encryption_data' do
          client.dialect = '0x0311'
          request_packet = client.smb2_3_negotiate_request
          allow(client).to receive(:negotiate_request).and_return(request_packet)
          allow(client).to receive(:negotiate_response).and_return(smb3_response)
          expect(client).to receive(:parse_smb3_encryption_data).with(request_packet, smb3_response)
          client.negotiate
        end
      end

      context 'with a wildcard revision number response' do
        before :example do
          client.dialect = '0x02ff'
          allow(client).to receive(:smb2_message_id=) do
            client.dialect = '0x0202'
          end
        end

        it 'increments the message ID' do
          expect(client).to receive(:smb2_message_id=).with(1)
          client.negotiate
        end

        it 're-negotiates' do
          expect(client).to receive(:negotiate_request).twice
          expect(client).to receive(:send_recv).twice
          expect(client).to receive(:negotiate_response).twice
          expect(client).to receive(:parse_negotiate_response).twice
          client.negotiate
        end
      end

      context 'when an error occurs' do
        before :example do
          allow(client).to receive(:negotiate_request).and_return(request_packet)
          allow(client).to receive(:send_recv).and_raise(RubySMB::Error::InvalidPacket)
          client.smb1 = false
          client.smb2 = false
          client.smb3 = false
        end

        context 'with SMB1' do
          let(:request_packet) { client.smb1_negotiate_request }

          it 'raise the expected exception' do
            client.smb1 = true
            expect { client.negotiate }.to raise_error(
              RubySMB::Error::NegotiationFailure,
              "Unable to negotiate SMB1 with the remote host: RubySMB::Error::InvalidPacket"
            )
          end
        end

        context 'with SMB2' do
          let(:request_packet) { client.smb2_3_negotiate_request }

          it 'raise the expected exception' do
            client.smb2 = true
            expect { client.negotiate }.to raise_error(
              RubySMB::Error::NegotiationFailure,
              "Unable to negotiate SMB2 with the remote host: RubySMB::Error::InvalidPacket"
            )
          end
        end

        context 'with SMB3' do
          let(:request_packet) { client.smb2_3_negotiate_request }

          it 'raise the expected exception' do
            client.smb3 = true
            expect { client.negotiate }.to raise_error(
              RubySMB::Error::NegotiationFailure,
              "Unable to negotiate SMB3 with the remote host: RubySMB::Error::InvalidPacket"
            )
          end
        end
      end

      describe '#parse_smb3_encryption_data' do
        let(:request_packet) { client.smb2_3_negotiate_request }
        let(:smb3_response) { RubySMB::SMB2::Packet::NegotiateResponse.new(dialect_revision: 0x311) }
        let(:nc_encryption) do
          nc = RubySMB::SMB2::NegotiateContext.new(
            context_type: RubySMB::SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES
          )
          nc.data.ciphers << RubySMB::SMB2::EncryptionCapabilities::AES_128_CCM
          nc
        end
        let(:nc_integrity) do
          nc = RubySMB::SMB2::NegotiateContext.new(
            context_type: RubySMB::SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES
          )
          nc.data.hash_algorithms << RubySMB::SMB2::PreauthIntegrityCapabilities::SHA_512
          nc
        end

        before :example do
          allow(smb3_client).to receive(:update_preauth_hash)
          smb3_response.add_negotiate_context(nc_encryption)
          smb3_response.add_negotiate_context(nc_integrity)
        end

        context 'when selecting the integrity hash algorithm' do
          context 'with one algorithm' do
            it 'selects the expected algorithm' do
              smb3_client.parse_smb3_encryption_data(request_packet, smb3_response)
              expect(smb3_client.preauth_integrity_hash_algorithm).to eq('SHA512')
            end
          end

          context 'with multiple algorithms' do
            it 'selects the first algorithm' do
              nc = smb3_response.find_negotiate_context(
                RubySMB::SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES
              )
              nc.data.hash_algorithms << 3
              smb3_client.parse_smb3_encryption_data(request_packet, smb3_response)
              expect(smb3_client.preauth_integrity_hash_algorithm).to eq('SHA512')
            end
          end

          context 'without integrity negotiate context' do
            it 'raises the expected exception' do
              smb3_response = RubySMB::SMB2::Packet::NegotiateResponse.new(dialect_revision: 0x311)
              smb3_response.add_negotiate_context(nc_encryption)
              expect { smb3_client.parse_smb3_encryption_data(request_packet, smb3_response) }.to raise_error(
                RubySMB::Error::EncryptionError,
                'Unable to retrieve the Preauth Integrity Hash Algorithm from the Negotiate response'
              )
            end
          end

          context 'with an unknown integrity hash algorithm' do
            it 'raises the expected exception' do
              smb3_response = RubySMB::SMB2::Packet::NegotiateResponse.new(dialect_revision: 0x311)
              smb3_response.add_negotiate_context(nc_encryption)
              nc = RubySMB::SMB2::NegotiateContext.new(
                context_type: RubySMB::SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES
              )
              nc.data.hash_algorithms << 5
              smb3_response.add_negotiate_context(nc)
              expect { smb3_client.parse_smb3_encryption_data(request_packet, smb3_response) }.to raise_error(
                RubySMB::Error::EncryptionError,
                'Unable to retrieve the Preauth Integrity Hash Algorithm from the Negotiate response'
              )
            end
          end
        end

        context 'when selecting the encryption algorithm' do
          context 'with one algorithm' do
            it 'selects the expected algorithm' do
              smb3_client.parse_smb3_encryption_data(request_packet, smb3_response)
              expect(smb3_client.encryption_algorithm).to eq('AES-128-CCM')
            end
          end

          context 'with multiple algorithms' do
            it 'selects the AES-128-GCM algorithm if included' do
              nc = smb3_response.find_negotiate_context(
                RubySMB::SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES
              )
              nc.data.ciphers << RubySMB::SMB2::EncryptionCapabilities::AES_128_GCM
              smb3_client.parse_smb3_encryption_data(request_packet, smb3_response)
              expect(smb3_client.encryption_algorithm).to eq('AES-128-GCM')
            end

            it 'selects the first algorithm if AES-128-GCM is not included' do
              nc = smb3_response.find_negotiate_context(
                RubySMB::SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES
              )
              nc.data.ciphers << 3
              smb3_client.parse_smb3_encryption_data(request_packet, smb3_response)
              expect(smb3_client.encryption_algorithm).to eq('AES-128-CCM')
            end

            it 'keep tracks of the server supported algorithms' do
              nc = smb3_response.find_negotiate_context(
                RubySMB::SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES
              )
              nc.data.ciphers << RubySMB::SMB2::EncryptionCapabilities::AES_128_GCM
              smb3_client.parse_smb3_encryption_data(request_packet, smb3_response)
              expect(smb3_client.server_encryption_algorithms).to eq([1, 2])
            end
          end

          context 'without encryption context' do
            it 'raises the expected exception' do
              smb3_response = RubySMB::SMB2::Packet::NegotiateResponse.new(dialect_revision: 0x311)
              smb3_response.add_negotiate_context(nc_integrity)
              expect { smb3_client.parse_smb3_encryption_data(request_packet, smb3_response) }.to raise_error(
                RubySMB::Error::EncryptionError,
                'Unable to retrieve the encryption cipher list supported by the server from the Negotiate response'
              )
            end
          end

          context 'with an unknown encryption algorithm' do
            it 'raises the expected exception' do
              smb3_response = RubySMB::SMB2::Packet::NegotiateResponse.new(dialect_revision: 0x311)
              smb3_response.add_negotiate_context(nc_integrity)
              nc = RubySMB::SMB2::NegotiateContext.new(
                context_type: RubySMB::SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES
              )
              nc.data.ciphers << 14
              smb3_response.add_negotiate_context(nc)
              expect { smb3_client.parse_smb3_encryption_data(request_packet, smb3_response) }.to raise_error(
                RubySMB::Error::EncryptionError,
                'Unable to retrieve the encryption cipher list supported by the server from the Negotiate response'
              )
            end
          end
        end

        context 'when selecting the compression algorithm' do
          it 'keep tracks of the server supported algorithms' do
            nc = RubySMB::SMB2::NegotiateContext.new(
              context_type: RubySMB::SMB2::NegotiateContext::SMB2_COMPRESSION_CAPABILITIES
            )
            nc.data.compression_algorithms << RubySMB::SMB2::CompressionCapabilities::LZNT1
            nc.data.compression_algorithms << RubySMB::SMB2::CompressionCapabilities::LZ77
            nc.data.compression_algorithms << RubySMB::SMB2::CompressionCapabilities::LZ77_Huffman
            nc.data.compression_algorithms << RubySMB::SMB2::CompressionCapabilities::Pattern_V1
            smb3_response.add_negotiate_context(nc)
            smb3_client.parse_smb3_encryption_data(request_packet, smb3_response)
            expect(smb3_client.server_compression_algorithms).to eq([1, 2, 3, 4])
          end
        end

        it 'updates the preauth hash' do
          expect(smb3_client).to receive(:update_preauth_hash).with(request_packet)
          expect(smb3_client).to receive(:update_preauth_hash).with(smb3_response)
          smb3_client.parse_smb3_encryption_data(request_packet, smb3_response)
        end
      end
    end
  end

  context 'Authentication' do
    let(:type2_string) {
      "TlRMTVNTUAACAAAAHgAeADgAAAA1goriwmZ8HEHtFHAAAAAAAAAAAJgAmABW\nAAAABgGxHQAAAA" \
        "9XAEkATgAtAFMATgBKAEQARwAwAFUAQQA5ADAARgACAB4A\nVwBJAE4ALQBTAE4ASgBEAEcAMABV" \
        "AEEAOQAwAEYAAQAeAFcASQBOAC0AUwBO\nAEoARABHADAAVQBBADkAMABGAAQAHgBXAEkATgAtAF" \
        "MATgBKAEQARwAwAFUA\nQQA5ADAARgADAB4AVwBJAE4ALQBTAE4ASgBEAEcAMABVAEEAOQAwAEYABw" \
        "AI\nADxThZ4nnNIBAAAAAA==\n"
    }

    describe '#authenticate' do
      it 'calls #smb2_authenticate if SMB2 was selected/negotiated' do
        expect(smb2_client).to receive(:smb2_authenticate)
        smb2_client.authenticate
      end

      it 'calls #smb1_authenticate if SMB1 was selected and we have credentials' do
        expect(smb1_client).to receive(:smb1_authenticate)
        smb1_client.authenticate
      end

      it 'calls #smb1_anonymous_auth if using SMB1 and no credentials were supplied' do
        smb1_client.username = ''
        smb1_client.password = ''
        expect(smb1_client).to receive(:smb1_anonymous_auth)
        smb1_client.authenticate
      end
    end

    context 'for SMB1' do
      let(:ntlm_client) { smb1_client.ntlm_client }
      let(:type1_message) { ntlm_client.init_context }
      let(:negotiate_packet) { RubySMB::SMB1::Packet::SessionSetupRequest.new }
      let(:response_packet) { RubySMB::SMB1::Packet::SessionSetupResponse.new }
      let(:final_response_packet) { RubySMB::SMB1::Packet::SessionSetupResponse.new }
      let(:type3_message) { ntlm_client.init_context(type2_string) }
      let(:user_id) { 2041 }

      describe '#smb1_authenticate' do
        before :example do
          allow(smb1_client).to receive(:smb1_ntlmssp_negotiate)
          allow(smb1_client).to receive(:smb1_ntlmssp_challenge_packet).and_return(response_packet)
          allow(smb1_client).to receive(:smb1_type2_message).and_return(type2_string)
          allow(smb1_client).to receive(:smb1_ntlmssp_authenticate)
          allow(smb1_client).to receive(:smb1_ntlmssp_final_packet).and_return(final_response_packet)
        end

        it 'calls the backing methods' do
          response_packet.smb_header.uid = user_id
          expect(smb1_client).to receive(:smb1_ntlmssp_negotiate).and_return(negotiate_packet)
          expect(smb1_client).to receive(:smb1_ntlmssp_challenge_packet).with(negotiate_packet).and_return(response_packet)
          expect(smb1_client).to receive(:smb1_type2_message).with(response_packet).and_return(type2_string)
          expect(smb1_client).to receive(:store_target_info).with(String)
          expect(smb1_client).to receive(:extract_os_version).with(String)
          expect(smb1_client).to receive(:smb1_ntlmssp_authenticate).with(Net::NTLM::Message::Type3, user_id)
          expect(smb1_client).to receive(:smb1_ntlmssp_final_packet).and_return(final_response_packet)
          smb1_client.smb1_authenticate
        end

        it 'stores the OS information from the challenge packet' do
          native_os = 'Windows 7 Professional 7601 Service Pack 1'
          native_lm = 'Windows 7 Professional 6.1'
          response_packet.data_block.native_os = native_os
          response_packet.data_block.native_lan_man = native_lm
          smb1_client.smb1_authenticate

          expect(smb1_client.peer_native_os).to eq native_os
          expect(smb1_client.peer_native_lm).to eq native_lm
        end

        it 'stores the session key from the NTLM client' do
          smb1_client.smb1_authenticate
          expect(smb1_client.session_key).to eq ntlm_client.session_key
        end

        it 'stores the OS version number from the challenge message' do
          smb1_client.smb1_authenticate
          expect(smb1_client.os_version).to eq '6.1.7601'
        end

        it 'stores the user ID if the status code is \'STATUS_SUCCESS\'' do
          response_packet.smb_header.uid = user_id
          final_response_packet.smb_header.nt_status = WindowsError::NTStatus::STATUS_SUCCESS.value
          smb1_client.smb1_authenticate
          expect(smb1_client.user_id).to eq user_id
        end

        it 'does not store the user ID if the status code is not \'STATUS_SUCCESS\'' do
          response_packet.smb_header.uid = user_id
          final_response_packet.smb_header.nt_status = WindowsError::NTStatus::STATUS_PENDING.value
          smb1_client.smb1_authenticate
          expect(smb1_client.user_id).to eq nil
        end
      end

      describe '#smb1_ntlmssp_auth_packet' do
        it 'creates a new SessionSetupRequest packet' do
          expect(RubySMB::SMB1::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          smb1_client.smb1_ntlmssp_auth_packet(type3_message, user_id)
        end

        it 'sets the security blob with an NTLM Type 3 Message' do
          expect(RubySMB::SMB1::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          expect(negotiate_packet).to receive(:set_type3_blob).with(type3_message.serialize)
          smb1_client.smb1_ntlmssp_auth_packet(type3_message, user_id)
        end

        it 'enables extended security on the packet' do
          expect(smb1_client.smb1_ntlmssp_auth_packet(type3_message, user_id).smb_header.flags2.extended_security).to eq 1
        end

        it 'sets the max_buffer_size to the client\'s max_buffer_size' do
          expect(smb1_client.smb1_ntlmssp_auth_packet(type3_message, user_id).parameter_block.max_buffer_size).to eq smb1_client.max_buffer_size
        end
      end

      describe '#smb1_ntlmssp_negotiate_packet' do
        it 'creates a new SessionSetupRequest packet' do
          expect(RubySMB::SMB1::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          smb1_client.smb1_ntlmssp_negotiate_packet
        end

        it 'builds the security blob with an NTLM Type 1 Message' do
          expect(RubySMB::SMB1::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          expect(ntlm_client).to receive(:init_context).and_return(type1_message)
          expect(negotiate_packet).to receive(:set_type1_blob).with(type1_message.serialize)
          smb1_client.smb1_ntlmssp_negotiate_packet
        end

        it 'enables extended security on the packet' do
          expect(smb1_client.smb1_ntlmssp_negotiate_packet.smb_header.flags2.extended_security).to eq 1
        end

        it 'sets the max_buffer_size to the client\'s max_buffer_size' do
          expect(smb1_client.smb1_ntlmssp_negotiate_packet.parameter_block.max_buffer_size).to eq smb1_client.max_buffer_size
        end
      end

      describe '#smb1_ntlmssp_authenticate' do
        it 'sends the request packet and receives a response' do
          expect(smb1_client).to receive(:smb1_ntlmssp_auth_packet).and_return(negotiate_packet)
          expect(dispatcher).to receive(:send_packet).with(negotiate_packet)
          expect(dispatcher).to receive(:recv_packet)
          smb1_client.smb1_ntlmssp_authenticate(type3_message, user_id)
        end
      end

      describe '#smb1_ntlmssp_negotiate' do
        it 'sends the request packet and receives a response' do
          expect(smb1_client).to receive(:smb1_ntlmssp_negotiate_packet).and_return(negotiate_packet)
          expect(dispatcher).to receive(:send_packet).with(negotiate_packet)
          expect(dispatcher).to receive(:recv_packet)
          smb1_client.smb1_ntlmssp_negotiate
        end
      end

      describe '#smb1_ntlmssp_challenge_packet' do
        let(:response) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.smb_header.nt_status = 0xc0000016
          packet
        }
        let(:wrong_command) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.smb_header.nt_status = 0xc0000016
          packet.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
          packet
        }
        it 'returns the packet object' do
          expect(smb1_client.smb1_ntlmssp_challenge_packet(response.to_binary_s)).to eq response
        end

        it 'raises an UnexpectedStatusCode if the status code is not correct' do
          response.smb_header.nt_status = 0xc0000015
          expect { smb1_client.smb1_ntlmssp_challenge_packet(response.to_binary_s) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
        end

        it 'raise an InvalidPacket exception when the response is not valid' do
          expect { smb1_client.smb1_ntlmssp_challenge_packet(wrong_command.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      describe '#smb1_ntlmssp_final_packet' do
        let(:response) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.smb_header.nt_status = 0x00000000
          packet
        }
        let(:wrong_command) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.smb_header.nt_status = 0x00000000
          packet.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
          packet
        }
        it 'returns the packet object' do
          expect(smb1_client.smb1_ntlmssp_final_packet(response.to_binary_s)).to eq response
        end

        it 'raise an InvalidPacket exception when the response is not valid' do
          expect { smb1_client.smb1_ntlmssp_final_packet(wrong_command.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      describe '#smb1_type2_message' do
        let(:fake_type2) { 'NTLMSSP FOO' }
        let(:response_packet) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.set_type2_blob(fake_type2)
          packet
        }
        it 'returns a base64 encoded copy of the Type 2 NTLM message' do
          expect(smb1_client.smb1_type2_message(response_packet)).to eq [fake_type2].pack('m')
        end
      end

      describe 'Anonymous Auth' do
        let(:anonymous_request) { RubySMB::SMB1::Packet::SessionSetupLegacyRequest.new }
        let(:anonymous_response) { RubySMB::SMB1::Packet::SessionSetupLegacyResponse.new }

        describe '#smb1_anonymous_auth' do
          it 'calls the backing methods' do
            expect(client).to receive(:smb1_anonymous_auth_request).and_return(anonymous_request)
            expect(client).to receive(:send_recv).with(anonymous_request)
            expect(client).to receive(:smb1_anonymous_auth_response).and_return(anonymous_response)
            client.smb1_anonymous_auth
          end

          it 'returns the status code' do
            allow(client).to receive(:send_recv)
            allow(client).to receive(:smb1_anonymous_auth_response).and_return(anonymous_response)
            anonymous_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_PENDING.value
            expect(client.smb1_anonymous_auth).to eq WindowsError::NTStatus::STATUS_PENDING
          end

          it 'sets the expected Client\'s attribute from the response when the status code is STATUS_SUCCESS' do
            native_os = 'Windows 7 Professional 7601 Service Pack 1'
            native_lm = 'Windows 7 Professional 6.1'
            primary_domain = 'SPEC_DOMAIN'
            anonymous_response.smb_header.uid = user_id
            anonymous_response.data_block.native_os = native_os
            anonymous_response.data_block.native_lan_man = native_lm
            anonymous_response.data_block.primary_domain = primary_domain
            anonymous_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_SUCCESS.value

            allow(client).to receive(:send_recv)
            allow(client).to receive(:smb1_anonymous_auth_response).and_return(anonymous_response)

            client.smb1_anonymous_auth
            expect(client.user_id).to eq user_id
            expect(client.peer_native_os).to eq native_os
            expect(client.peer_native_lm).to eq native_lm
            expect(client.primary_domain).to eq primary_domain
          end
        end

        describe '#smb1_anonymous_auth_request' do
          it 'creates a SessionSetupLegacyRequest packet with a null byte for the oem password' do
            expect(smb1_client.smb1_anonymous_auth_request.data_block.oem_password).to eq "\x00"
          end

          it 'creates a SessionSetupLegacyRequest packet with the max_buffer_size set to the client\'s max_buffer_size' do
            expect(smb1_client.smb1_anonymous_auth_request.parameter_block.max_buffer_size).to eq smb1_client.max_buffer_size
          end
        end

        describe '#smb1_anonymous_auth_response' do
          it 'returns a Legacy Session SetupResponse Packet' do
            expect(smb1_client.smb1_anonymous_auth_response(anonymous_response.to_binary_s)).to eq anonymous_response
          end

          it 'raise an InvalidPacket exception when the response is not valid' do
            anonymous_response.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
            expect { smb1_client.smb1_anonymous_auth_response(anonymous_response.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
          end
        end
      end
    end

    context 'for SMB2' do
      let(:ntlm_client) { smb2_client.ntlm_client }
      let(:type1_message) { ntlm_client.init_context }
      let(:negotiate_packet) { RubySMB::SMB2::Packet::SessionSetupRequest.new }
      let(:response_packet) { RubySMB::SMB2::Packet::SessionSetupResponse.new }
      let(:final_response_packet) { RubySMB::SMB2::Packet::SessionSetupResponse.new }
      let(:type3_message) { ntlm_client.init_context(type2_string) }
      let(:session_id) { 0x0000040000000005 }

      describe '#smb2_authenticate' do
        before :example do
          allow(smb2_client).to receive(:smb2_ntlmssp_negotiate)
          allow(smb2_client).to receive(:smb2_ntlmssp_challenge_packet).and_return(response_packet)
          allow(smb2_client).to receive(:smb2_type2_message).and_return(type2_string)
          allow(smb2_client).to receive(:smb2_ntlmssp_authenticate)
          allow(smb2_client).to receive(:smb2_ntlmssp_final_packet).and_return(final_response_packet)
        end

        it 'calls the backing methods' do
          response_packet.smb2_header.session_id = session_id
          expect(smb2_client).to receive(:smb2_ntlmssp_negotiate).and_return(negotiate_packet)
          expect(smb2_client).to receive(:smb2_ntlmssp_challenge_packet).with(negotiate_packet).and_return(response_packet)
          expect(smb2_client).to receive(:smb2_type2_message).with(response_packet).and_return(type2_string)
          expect(smb2_client).to receive(:store_target_info).with(String)
          expect(smb2_client).to receive(:extract_os_version).with(String)
          expect(smb2_client).to receive(:smb2_ntlmssp_authenticate).with(Net::NTLM::Message::Type3, session_id)
          expect(smb2_client).to receive(:smb2_ntlmssp_final_packet).and_return(final_response_packet)
          smb2_client.smb2_authenticate
        end

        it 'stores the session ID from the challenge message' do
          response_packet.smb2_header.session_id = session_id
          smb2_client.smb2_authenticate
          expect(smb2_client.session_id).to eq session_id
        end

        it 'stores the session key from the NTLM client' do
          smb2_client.smb2_authenticate
          expect(smb2_client.session_key).to eq ntlm_client.session_key
        end

        it 'stores the OS version number from the challenge message' do
          smb2_client.smb2_authenticate
          expect(smb2_client.os_version).to eq '6.1.7601'
        end

        ['0x0202', '0x0210', '0x0300', '0x0302'].each do |dialect|
          it "does not update the preauth hash with dialect #{dialect}" do
            smb2_client.dialect = dialect
            expect(smb2_client).to_not receive(:update_preauth_hash)
            smb2_client.smb2_authenticate
          end
        end

        it "updates the preauth hash with dialect 0x0311" do
          smb2_client.dialect = '0x0311'
          expect(smb2_client).to receive(:update_preauth_hash).with(response_packet)
          smb2_client.smb2_authenticate
        end

        context 'when setting the encryption_required parameter' do
          before :example do
            smb2_client.smb3 = true
            smb2_client.encryption_required = false
          end

          it 'sets the encryption_required parameter to true if the server requires encryption' do
            final_response_packet.session_flags.encrypt_data = 1
            smb2_client.smb2_authenticate
            expect(smb2_client.encryption_required).to be true
          end

          it 'does not set the encryption_required parameter if the server does not require encryption' do
            final_response_packet.session_flags.encrypt_data = 0
            smb2_client.smb2_authenticate
            expect(smb2_client.encryption_required).to be false
          end
        end
      end

      describe '#smb2_ntlmssp_negotiate_packet' do
        it 'creates a new SessionSetupRequest packet' do
          expect(RubySMB::SMB2::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          smb2_client.smb2_ntlmssp_negotiate_packet
        end

        it 'builds the security blob with an NTLM Type 1 Message' do
          expect(RubySMB::SMB2::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          expect(ntlm_client).to receive(:init_context).and_return(type1_message)
          expect(negotiate_packet).to receive(:set_type1_blob).with(type1_message.serialize)
          smb2_client.smb2_ntlmssp_negotiate_packet
        end

        it 'enables signing' do
          expect(smb2_client.smb2_ntlmssp_negotiate_packet.security_mode.signing_enabled).to eq 1
        end
      end

      describe '#smb2_ntlmssp_negotiate' do
        before :example do
          allow(smb2_client).to receive(:smb2_ntlmssp_negotiate_packet).and_return(negotiate_packet)
          allow(smb2_client).to receive(:send_recv)
        end

        it 'sends the request packet and receives a response' do
          expect(smb2_client).to receive(:smb2_ntlmssp_negotiate_packet)
          expect(smb2_client).to receive(:send_recv).with(negotiate_packet)
          smb2_client.smb2_ntlmssp_negotiate
        end

        ['0x0202', '0x0210', '0x0300', '0x0302'].each do |dialect|
          it "does not update the preauth hash with dialect #{dialect}" do
            smb2_client.dialect = dialect
            expect(smb2_client).to_not receive(:update_preauth_hash)
            smb2_client.smb2_ntlmssp_negotiate
          end
        end

        it "updates the preauth hash with dialect 0x0311" do
          smb2_client.dialect = '0x0311'
          expect(smb2_client).to receive(:update_preauth_hash).with(negotiate_packet)
          smb2_client.smb2_ntlmssp_negotiate
        end
      end

      describe '#smb2_ntlmssp_challenge_packet' do
        let(:response) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.smb2_header.nt_status = 0xc0000016
          packet
        }
        let(:wrong_command) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.smb2_header.nt_status = 0xc0000016
          packet.smb2_header.command = RubySMB::SMB2::Commands::NEGOTIATE
          packet
        }
        it 'returns the packet object' do
          expect(smb2_client.smb2_ntlmssp_challenge_packet(response.to_binary_s)).to eq response
        end

        it 'raises an UnexpectedStatusCode if the status code is not correct' do
          response.smb2_header.nt_status = 0xc0000015
          expect { smb2_client.smb2_ntlmssp_challenge_packet(response.to_binary_s) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
        end

        it 'raise an InvalidPacket exception when the response is not valid' do
          expect { smb2_client.smb2_ntlmssp_challenge_packet(wrong_command.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      describe '#smb2_type2_message' do
        let(:fake_type2) { 'NTLMSSP FOO' }
        let(:response_packet) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.set_type2_blob(fake_type2)
          packet
        }
        it 'returns a base64 encoded copy of the Type 2 NTLM message' do
          expect(smb2_client.smb2_type2_message(response_packet)).to eq [fake_type2].pack('m')
        end
      end

      describe '#smb2_ntlmssp_auth_packet' do
        it 'creates a new SessionSetupRequest packet' do
          expect(RubySMB::SMB2::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          smb2_client.smb2_ntlmssp_auth_packet(type3_message, session_id)
        end

        it 'sets the security blob with an NTLM Type 3 Message' do
          expect(RubySMB::SMB2::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          expect(negotiate_packet).to receive(:set_type3_blob).with(type3_message.serialize)
          smb2_client.smb2_ntlmssp_auth_packet(type3_message, session_id)
        end

        it 'sets the session ID on the request packet' do
          expect(smb2_client.smb2_ntlmssp_auth_packet(type3_message, session_id).smb2_header.session_id).to eq session_id
        end

        it 'enables signing' do
          expect(smb2_client.smb2_ntlmssp_auth_packet(type3_message, session_id).security_mode.signing_enabled).to eq 1
        end
      end

      describe '#smb2_ntlmssp_authenticate' do
        before :example do
          allow(smb2_client).to receive(:smb2_ntlmssp_auth_packet).and_return(negotiate_packet)
          allow(smb2_client).to receive(:send_recv)
        end

        it 'sends the request packet and receives a response' do
          expect(smb2_client).to receive(:smb2_ntlmssp_auth_packet)
          expect(smb2_client).to receive(:send_recv).with(negotiate_packet)
          smb2_client.smb2_ntlmssp_authenticate(type3_message, session_id)
        end

        ['0x0202', '0x0210', '0x0300', '0x0302'].each do |dialect|
          it "does not update the preauth hash with dialect #{dialect}" do
            smb2_client.dialect = dialect
            expect(smb2_client).to_not receive(:update_preauth_hash)
            smb2_client.smb2_ntlmssp_authenticate(type3_message, session_id)
          end
        end

        it "updates the preauth hash with dialect 0x0311" do
          smb2_client.dialect = '0x0311'
          expect(smb2_client).to receive(:update_preauth_hash).with(negotiate_packet)
          smb2_client.smb2_ntlmssp_authenticate(type3_message, session_id)
        end
      end

      describe '#smb2_ntlmssp_final_packet' do
        let(:response) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.smb2_header.nt_status = 0x00000000
          packet
        }
        let(:wrong_command) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.smb2_header.nt_status = 0x00000000
          packet.smb2_header.command = RubySMB::SMB2::Commands::NEGOTIATE
          packet
        }
        it 'returns the packet object' do
          expect(smb2_client.smb2_ntlmssp_final_packet(response.to_binary_s)).to eq response
        end

        it 'raise an InvalidPacket exception when the response is not valid' do
          expect { smb2_client.smb2_ntlmssp_final_packet(wrong_command.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end
    end

    describe '#store_target_info' do
      let(:target_info_str) { "\x02\x00\x14\x00T\x00E\x00S\x00T\x00D\x00O\x00M"\
        "\x00A\x00I\x00N\x00\x01\x00\x10\x00T\x00E\x00S\x00T\x00N\x00A\x00M"\
        "\x00E\x00\x04\x00 \x00t\x00e\x00s\x00t\x00d\x00o\x00m\x00a\x00i\x00"\
        "n\x00.\x00l\x00o\x00c\x00a\x00l\x00\x03\x002\x00t\x00e\x00s\x00t\x00"\
        "n\x00a\x00m\x00e\x00.\x00t\x00e\x00s\x00t\x00d\x00o\x00m\x00a\x00i"\
        "\x00n\x00.\x00l\x00o\x00c\x00a\x00l\x00\x05\x00 \x00t\x00e\x00s\x00t"\
        "\x00f\x00o\x00r\x00e\x00s\x00t\x00.\x00l\x00o\x00c\x00a\x00l\x00\a"\
        "\x00\b\x00Q7w\x01Fh\xD3\x01\x00\x00\x00\x00" }

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
  end

  context 'Signing' do
    describe '#smb2_sign' do
      let(:request1) {
        packet = RubySMB::SMB2::Packet::SessionSetupRequest.new
        packet.smb2_header.flags.signed = 1
        packet.smb2_header.signature = "\x00" * 16
        packet
      }
      let(:fake_hmac) { "\x31\x07\x78\x3e\x35\xd7\x0e\x89\x08\x43\x8a\x18\xcd\x78\x52\x39".force_encoding('ASCII-8BIT') }

      context 'if signing is required and we have a session key' do
        it 'generates the HMAC based on the packet and the NTLM session key and signs the packet with it' do
          smb2_client.session_key = 'foo'
          smb2_client.signing_required = true
          expect(OpenSSL::HMAC).to receive(:digest).with(instance_of(OpenSSL::Digest::SHA256), smb2_client.session_key, request1.to_binary_s).and_return(fake_hmac)
          expect(smb2_client.smb2_sign(request1).smb2_header.signature).to eq fake_hmac
        end
      end

      context 'when signing is not required' do
        it 'returns the packet exactly as it was given' do
          smb2_client.session_key = 'foo'
          smb2_client.signing_required = false
          expect(smb2_client.smb2_sign(request1)).to eq request1
        end
      end

      context 'when there is no session_key' do
        it 'returns the packet exactly as it was given' do
          smb2_client.session_key = ''
          smb2_client.signing_required = true
          expect(smb2_client.smb2_sign(request1)).to eq request1
        end
      end
    end

    describe '#smb1_sign' do
      let(:request1) { RubySMB::SMB1::Packet::SessionSetupRequest.new }
      let(:fake_sig) { "\x9f\x62\xcf\x08\xd9\xc2\x83\x21".force_encoding('ASCII-8BIT') }

      context 'if signing is required and we have a session key' do
        it 'generates the signature based on the packet, the sequence counter and the NTLM session key and signs the packet with it' do
          smb1_client.session_key = 'foo'
          smb1_client.signing_required = true
          raw = request1.to_binary_s
          adjusted_request = RubySMB::SMB1::Packet::SessionSetupRequest.read(raw)
          adjusted_request.smb_header.security_features = [smb1_client.sequence_counter].pack('Q<')
          expect(OpenSSL::Digest::MD5).to receive(:digest).and_return(fake_sig)
          expect(smb1_client.smb1_sign(request1).smb_header.security_features).to eq fake_sig
        end
      end

      context 'when signing is not required' do
        it 'returns the packet exactly as it was given' do
          smb1_client.session_key = 'foo'
          smb1_client.signing_required = false
          expect(smb1_client.smb1_sign(request1)).to eq request1
        end
      end

      context 'when there is no session_key' do
        it 'returns the packet exactly as it was given' do
          smb1_client.session_key = ''
          smb1_client.signing_required = true
          expect(smb1_client.smb1_sign(request1)).to eq request1
        end
      end
    end

    describe '#smb3_sign' do
      context 'if signing is required and we have a session key' do
        let(:request) {
          packet = RubySMB::SMB2::Packet::SessionSetupRequest.new
          packet.smb2_header.flags.signed = 1
          packet.smb2_header.signature = "\x00" * 16
          packet
        }
        let(:session_key) { 'Session Key' }
        before :example do
          smb3_client.session_key = session_key
          smb3_client.signing_required = true
        end

        ['0x0300', '0x0302'].each do |dialect|
          context "with #{dialect} dialect" do
            it 'generates the signing key based on the session key and specific strings, and sign the packet with CMAC' do
              smb3_client.dialect = dialect
              fake_hash = "\x34\xc0\x40\xfe\x87\xcf\x49\x3d\x37\x87\x52\xd0\xd5\xf5\xfb\x86".b
              signing_key = RubySMB::Crypto::KDF.counter_mode(session_key, "SMB2AESCMAC\x00", "SmbSign\x00")
              expect(RubySMB::Crypto::KDF).to receive(:counter_mode).with(session_key, "SMB2AESCMAC\x00", "SmbSign\x00").and_call_original
              expect(OpenSSL::CMAC).to receive(:digest).with('AES', signing_key, request.to_binary_s).and_call_original
              expect(smb3_client.smb3_sign(request).smb2_header.signature).to eq fake_hash
            end
          end
        end

        context "with 0x0311 dialect" do
          it 'generates the signing key based on the session key, the preauth integrity hash and specific strings, and sign the packet with CMAC' do
            smb3_client.dialect = '0x0311'
            preauth_integrity_hash_value = 'Preauth Integrity Hash'
            fake_hash = "\x0e\x49\x6f\x8e\x74\x7c\xf2\xa0\x88\x5e\x9d\x54\xff\x0d\x0d\xfa".b
            smb3_client.preauth_integrity_hash_value = preauth_integrity_hash_value
            signing_key = RubySMB::Crypto::KDF.counter_mode(session_key, "SMBSigningKey\x00", preauth_integrity_hash_value)
            expect(RubySMB::Crypto::KDF).to receive(:counter_mode).with(session_key, "SMBSigningKey\x00", preauth_integrity_hash_value).and_call_original
            expect(OpenSSL::CMAC).to receive(:digest).with('AES', signing_key, request.to_binary_s).and_call_original
            expect(smb3_client.smb3_sign(request).smb2_header.signature).to eq fake_hash
          end
        end

        context 'with an incompatible dialect' do
          it 'raises the expected exception' do
            smb3_client.dialect = '0x0202'
            expect { smb3_client.smb3_sign(request) }.to raise_error(
              RubySMB::Error::SigningError,
              'Dialect is incompatible with SMBv3 signing'
            )
          end
        end
      end

      context 'if signing is not required but it is a TreeConnectRequest and we have a session key' do
        let(:request) {
          packet = RubySMB::SMB2::Packet::TreeConnectRequest.new
          packet.smb2_header.flags.signed = 1
          packet.smb2_header.signature = "\x00" * 16
          packet
        }
        let(:session_key) { 'Session Key' }
        before :example do
          smb3_client.session_key = session_key
          smb3_client.signing_required = false
        end

        ['0x0300', '0x0302'].each do |dialect|
          context "with #{dialect} dialect" do
            it 'generates the signing key based on the session key and specific strings, and sign the packet with CMAC' do
              smb3_client.dialect = dialect
              fake_hash = "\x34\x9e\x28\xb9\x50\x08\x34\x31\xc0\x83\x9d\xba\x56\xa5\x70\xa4".b
              signing_key = RubySMB::Crypto::KDF.counter_mode(session_key, "SMB2AESCMAC\x00", "SmbSign\x00")
              expect(RubySMB::Crypto::KDF).to receive(:counter_mode).with(session_key, "SMB2AESCMAC\x00", "SmbSign\x00").and_call_original
              expect(OpenSSL::CMAC).to receive(:digest).with('AES', signing_key, request.to_binary_s).and_call_original
              expect(smb3_client.smb3_sign(request).smb2_header.signature).to eq fake_hash
            end
          end
        end

        context "with 0x0311 dialect" do
          it 'generates the signing key based on the session key, the preauth integrity hash and specific strings, and sign the packet with CMAC' do
            smb3_client.dialect = '0x0311'
            preauth_integrity_hash_value = 'Preauth Integrity Hash'
            fake_hash = "\x83\xd9\x31\x39\x60\x46\xbe\x1e\x29\x34\xc8\xcf\x8c\x8e\xb4\x73".b
            smb3_client.preauth_integrity_hash_value = preauth_integrity_hash_value
            signing_key = RubySMB::Crypto::KDF.counter_mode(session_key, "SMBSigningKey\x00", preauth_integrity_hash_value)
            expect(RubySMB::Crypto::KDF).to receive(:counter_mode).with(session_key, "SMBSigningKey\x00", preauth_integrity_hash_value).and_call_original
            expect(OpenSSL::CMAC).to receive(:digest).with('AES', signing_key, request.to_binary_s).and_call_original
            expect(smb3_client.smb3_sign(request).smb2_header.signature).to eq fake_hash
          end
        end

        context 'with an incompatible dialect' do
          it 'raises the expected exception' do
            smb3_client.dialect = '0x0202'
            expect { smb3_client.smb3_sign(request) }.to raise_error(
              RubySMB::Error::SigningError,
              'Dialect is incompatible with SMBv3 signing'
            )
          end
        end
      end
    end
  end

  context '#increment_smb_message_id' do
    let(:request_packet) { RubySMB::SMB2::Packet::NegotiateRequest.new }

    it 'sets the message_id on the packet header to the client message_id' do
      id = client.smb2_message_id
      expect(client.increment_smb_message_id(request_packet).smb2_header.message_id).to eq id
    end

    it 'increments the client message id' do
      client.smb2_message_id = 1
      expect { client.increment_smb_message_id(request_packet) }.to change { client.smb2_message_id }.by(1)
    end
  end

  context 'connecting to a share' do
    let(:path) { '\\192.168.1.1\example' }
    let(:tree_id) { 2049 }
    context 'with SMB1' do
      let(:request) { RubySMB::SMB1::Packet::TreeConnectRequest.new }
      let(:response) {
        packet = RubySMB::SMB1::Packet::TreeConnectResponse.new
        packet.smb_header.tid = tree_id
        packet.parameter_block.access_rights.read("\xff\x01\x1f\x00")
        packet.data_block.service = 'A:'
        packet
      }

      describe '#smb1_tree_connect' do
        it 'builds and sends a TreeconnectRequest for the supplied share' do
          allow(RubySMB::SMB1::Packet::TreeConnectRequest).to receive(:new).and_return(request)
          modified_request = request
          modified_request.data_block.path = path
          expect(smb1_client).to receive(:send_recv).with(modified_request).and_return(response.to_binary_s)
          smb1_client.smb1_tree_connect(path)
        end

        it 'sends the response to #smb1_tree_from_response' do
          expect(smb1_client).to receive(:send_recv).and_return(response.to_binary_s)
          expect(smb1_client).to receive(:smb1_tree_from_response).with(path, response)
          smb1_client.smb1_tree_connect(path)
        end
      end

      describe '#smb1_tree_from_response' do
        it 'raises an InvalidPacket exception if the command is not TREE_CONNECT' do
          response.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
          expect { smb1_client.smb1_tree_from_response(path, response) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'raises an UnexpectedStatusCode exception if we do not get STATUS_SUCCESS' do
          response.smb_header.nt_status = 0xc0000015
          expect { smb1_client.smb1_tree_from_response(path, response) }.to raise_error(
            RubySMB::Error::UnexpectedStatusCode,
            'The server responded with an unexpected status code: STATUS_NONEXISTENT_SECTOR'
          )
        end

        it 'creates a new Tree from itself, the share path, and the response packet' do
          expect(RubySMB::SMB1::Tree).to receive(:new).with(client: smb1_client, share: path, response: response)
          smb1_client.smb1_tree_from_response(path, response)
        end
      end
    end

    context 'with SMB2' do
      let(:request) { RubySMB::SMB2::Packet::TreeConnectRequest.new }
      let(:response) {
        packet = RubySMB::SMB2::Packet::TreeConnectResponse.new
        packet.smb2_header.tree_id = tree_id
        packet.maximal_access.read("\xff\x01\x1f\x00")
        packet.share_type = 0x01
        packet
      }

      describe '#smb2_tree_connect' do
        it 'builds and sends the expected TreeconnectRequest for the supplied share' do
          allow(RubySMB::SMB2::Packet::TreeConnectRequest).to receive(:new).and_return(request)
          expect(smb2_client).to receive(:send_recv) do |req|
            expect(req).to eq(request)
            expect(req.smb2_header.tree_id).to eq(65_535)
            expect(req.path).to eq(path.encode('UTF-16LE'))
            response.to_binary_s
          end
          smb2_client.smb2_tree_connect(path)
        end

        it 'sends the response to #smb2_tree_from_response' do
          expect(smb2_client).to receive(:send_recv).and_return(response.to_binary_s)
          expect(smb2_client).to receive(:smb2_tree_from_response).with(path, response)
          smb2_client.smb2_tree_connect(path)
        end
      end

      describe '#smb2_tree_from_response' do
        it 'raises an InvalidPacket exception if the command is not TREE_CONNECT' do
          response.smb2_header.command = RubySMB::SMB2::Commands::NEGOTIATE
          expect { smb2_client.smb2_tree_from_response(path, response) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'raises an UnexpectedStatusCode exception if we do not get STATUS_SUCCESS' do
          response.smb2_header.nt_status = 0xc0000015
          expect { smb2_client.smb2_tree_from_response(path, response) }.to raise_error(
            RubySMB::Error::UnexpectedStatusCode,
            'The server responded with an unexpected status code: STATUS_NONEXISTENT_SECTOR'
          )
        end

        it 'creates a new Tree from itself, the share path, and the response packet' do
          expect(RubySMB::SMB2::Tree).to receive(:new).with(client: smb2_client, share: path, response: response, encrypt: false)
          smb2_client.smb2_tree_from_response(path, response)
        end

        it 'creates a new with encryption set if the response requires it' do
          response.share_flags.encrypt = 1
          expect(RubySMB::SMB2::Tree).to receive(:new).with(client: smb2_client, share: path, response: response, encrypt: true)
          smb2_client.smb2_tree_from_response(path, response)
        end
      end

      describe '#net_share_enum_all' do
        let(:tree){ double("Tree") }
        let(:named_pipe){ double("Named Pipe") }

        before :example do
          allow(tree).to receive(:open_file).and_return(named_pipe)
          allow(named_pipe).to receive(:net_share_enum_all)
        end

        context 'with SMB1' do
          before :example do
            allow(smb1_client).to receive(:tree_connect).and_return(tree)
          end

          it 'it calls the #tree_connect method to connect to the "host" IPC$ share' do
            ipc_share = "\\\\#{sock.peeraddr}\\IPC$"
            expect(smb1_client).to receive(:tree_connect).with(ipc_share).and_return(tree)
            smb1_client.net_share_enum_all(sock.peeraddr)
          end

          it 'it calls the Tree #open_file method to open "srvsvc" named pipe' do
            expect(tree).to receive(:open_file).with(filename: "srvsvc", write: true, read: true).and_return(named_pipe)
            smb1_client.net_share_enum_all(sock.peeraddr)
          end

          it 'it calls the File #net_share_enum_all method with the correct host' do
            host = "1.2.3.4"
            expect(named_pipe).to receive(:net_share_enum_all).with(host)
            smb1_client.net_share_enum_all(host)
          end
        end

        context 'with SMB2' do
          before :example do
            allow(smb2_client).to receive(:tree_connect).and_return(tree)
          end

          it 'it calls the #tree_connect method to connect to the "host" IPC$ share' do
            ipc_share = "\\\\#{sock.peeraddr}\\IPC$"
            expect(smb2_client).to receive(:tree_connect).with(ipc_share).and_return(tree)
            smb2_client.net_share_enum_all(sock.peeraddr)
          end

          it 'it calls the Tree #open_file method to open "srvsvc" named pipe' do
            expect(tree).to receive(:open_file).with(filename: "srvsvc", write: true, read: true).and_return(named_pipe)
            smb2_client.net_share_enum_all(sock.peeraddr)
          end

          it 'it calls the File #net_share_enum_all method with the correct host' do
            host = "1.2.3.4"
            expect(named_pipe).to receive(:net_share_enum_all).with(host)
            smb2_client.net_share_enum_all(host)
          end
        end
      end
    end
  end

  context 'Echo command' do
    context 'with SMB1' do
      let(:echo_request) { RubySMB::SMB1::Packet::EchoRequest.new }
      let(:echo_response) {
        packet = RubySMB::SMB1::Packet::EchoResponse.new
        packet.smb_header.nt_status = 0x00000080
        packet
      }

      before(:each) do
        allow(RubySMB::SMB2::Packet::EchoRequest).to receive(:new).and_return(echo_request)
      end

      it 'sets the echo_count on the request packet' do
        modified_request = echo_request
        modified_request.parameter_block.echo_count = 5
        expect(smb1_client).to receive(:send_recv).with(modified_request).and_return(echo_response.to_binary_s)
        expect(dispatcher).to receive(:recv_packet).exactly(4).times.and_return(echo_response.to_binary_s)
        smb1_client.smb1_echo(count: 5)
      end

      it 'sets the data on the request packet' do
        modified_request = echo_request
        modified_request.data_block.data = 'DEADBEEF'
        expect(smb1_client).to receive(:send_recv).with(modified_request).and_return(echo_response.to_binary_s)
        smb1_client.smb1_echo(data: 'DEADBEEF')
      end

      it 'returns the NT status code' do
        expect(smb1_client).to receive(:send_recv).and_return(echo_response.to_binary_s)
        expect(smb1_client.echo).to eq WindowsError::NTStatus::STATUS_ABANDONED
      end

      it 'raise an InvalidPacket exception when the response is not valid' do
        echo_response.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_SESSION_SETUP_ANDX
        allow(smb1_client).to receive(:send_recv).and_return(echo_response.to_binary_s)
        expect { smb1_client.echo }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end

    context 'with SMB2' do
      let(:echo_request) { RubySMB::SMB2::Packet::EchoRequest.new }
      let(:echo_response) { RubySMB::SMB2::Packet::EchoResponse.new }

      it '#smb2_echo sends an Echo Request and returns a response' do
        allow(RubySMB::SMB2::Packet::EchoRequest).to receive(:new).and_return(echo_request)
        expect(smb2_client).to receive(:send_recv).with(echo_request).and_return(echo_response.to_binary_s)
        expect(smb2_client.smb2_echo).to eq echo_response
      end

      it 'raise an InvalidPacket exception when the response is not valid' do
        echo_response.smb2_header.command = RubySMB::SMB2::Commands::SESSION_SETUP
        allow(smb2_client).to receive(:send_recv).and_return(echo_response.to_binary_s)
        expect { smb2_client.smb2_echo }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end
  end

  context 'Winreg' do
    describe '#connect_to_winreg' do
      let(:host)       { '1.2.3.4' }
      let(:share)      { "\\\\#{host}\\IPC$" }
      let(:ipc_tree)   { double('IPC$ tree') }
      let(:named_pipe) { double('Named pipe') }
      before :example do
        allow(ipc_tree).to receive_messages(
          :share     => share,
          :open_file => named_pipe
        )
        allow(client).to receive(:tree_connect).and_return(ipc_tree)
      end

      context 'when the client is already connected to the IPC$ share' do
        before :example do
          client.tree_connects << ipc_tree
          allow(ipc_tree).to receive(:share).and_return(share)
        end

        it 'does not connect to the already connected tree' do
          client.connect_to_winreg(host)
          expect(client).to_not have_received(:tree_connect)
        end
      end

      it 'calls #tree_connect' do
        client.connect_to_winreg(host)
        expect(client).to have_received(:tree_connect).with(share)
      end

      it 'open \'winreg\' file on the IPC$ Tree' do
        client.connect_to_winreg(host)
        expect(ipc_tree).to have_received(:open_file).with(filename: "winreg", write: true, read: true)
      end

      it 'returns the expected opened named pipe' do
        expect(client.connect_to_winreg(host)).to eq(named_pipe)
      end

      context 'when a block is given' do
        before :example do
          allow(named_pipe).to receive(:close)
        end

        it 'yields the expected named_pipe' do
          client.connect_to_winreg(host) do |np|
            expect(np).to eq(named_pipe)
          end
        end

        it 'closes the named pipe' do
          client.connect_to_winreg(host) { |np| }
          expect(named_pipe).to have_received(:close)
        end

        it 'returns the block return value' do
          result = double('Result')
          expect(client.connect_to_winreg(host) { |np| result }).to eq(result)
        end
      end
    end

    describe '#has_registry_key?' do
      let(:host)       { '1.2.3.4' }
      let(:key)        { 'HKLM\\Registry\\Key' }
      let(:named_pipe) { double('Named pipe') }
      let(:result)     { double('Result') }
      before :example do
        allow(client).to receive(:connect_to_winreg).and_yield(named_pipe)
        allow(named_pipe).to receive(:has_registry_key?).and_return(result)
      end

      it 'calls #connect_to_winreg to wrap the main logic around' do
        client.has_registry_key?(host, key)
        expect(client).to have_received(:connect_to_winreg).with(host)
      end

      it 'calls Pipe #has_registry_key?' do
        client.has_registry_key?(host, key)
        expect(named_pipe).to have_received(:has_registry_key?).with(key)
      end
    end

    describe '#read_registry_key_value' do
      let(:host)        { '1.2.3.4' }
      let(:key)         { 'HKLM\\Registry\\Key' }
      let(:value_name)  { 'Value' }
      let(:named_pipe)  { double('Named pipe') }
      let(:result)      { double('Result') }
      before :example do
        allow(client).to receive(:connect_to_winreg).and_yield(named_pipe)
        allow(named_pipe).to receive(:read_registry_key_value).and_return(result)
      end

      it 'calls #connect_to_winreg to wrap the main logic around' do
        client.read_registry_key_value(host, key, value_name)
        expect(client).to have_received(:connect_to_winreg).with(host)
      end

      it 'calls Pipe #read_registry_key_value' do
        client.read_registry_key_value(host, key, value_name)
        expect(named_pipe).to have_received(:read_registry_key_value).with(key, value_name)
      end
    end

    describe '#enum_registry_key' do
      let(:host)       { '1.2.3.4' }
      let(:key)        { 'HKLM\\Registry\\Key' }
      let(:named_pipe) { double('Named pipe') }
      let(:result)     { double('Result') }
      before :example do
        allow(client).to receive(:connect_to_winreg).and_yield(named_pipe)
        allow(named_pipe).to receive(:enum_registry_key).and_return(result)
      end

      it 'calls #connect_to_winreg to wrap the main logic around' do
        client.enum_registry_key(host, key)
        expect(client).to have_received(:connect_to_winreg).with(host)
      end

      it 'calls Pipe #enum_registry_key' do
        client.enum_registry_key(host, key)
        expect(named_pipe).to have_received(:enum_registry_key).with(key)
      end
    end

    describe '#enum_registry_values' do
      let(:host)       { '1.2.3.4' }
      let(:key)        { 'HKLM\\Registry\\Key' }
      let(:named_pipe) { double('Named pipe') }
      let(:result)     { double('Result') }
      before :example do
        allow(client).to receive(:connect_to_winreg).and_yield(named_pipe)
        allow(named_pipe).to receive(:enum_registry_values).and_return(result)
      end

      it 'calls #connect_to_winreg to wrap the main logic around' do
        client.enum_registry_values(host, key)
        expect(client).to have_received(:connect_to_winreg).with(host)
      end

      it 'calls Pipe #enum_registry_values' do
        client.enum_registry_values(host, key)
        expect(named_pipe).to have_received(:enum_registry_values).with(key)
      end
    end
  end

  describe '#update_preauth_hash' do
    it 'raises an EncryptionError exception if the preauth integrity hash algorithm is not known' do
      expect { client.update_preauth_hash('Test') }.to raise_error(
        RubySMB::Error::EncryptionError,
        'Cannot compute the Preauth Integrity Hash value: Preauth Integrity Hash Algorithm is nil'
      )
    end

    it 'computes the hash value' do
      packet = RubySMB::SMB2::Packet::EchoRequest.new
      data = 'Previous hash'
      algo = RubySMB::SMB2::PreauthIntegrityCapabilities::HASH_ALGORITM_MAP[
        RubySMB::SMB2::PreauthIntegrityCapabilities::SHA_512
      ]
      client.preauth_integrity_hash_algorithm = algo
      client.preauth_integrity_hash_value = data
      hash = OpenSSL::Digest.digest(algo, data + packet.to_binary_s)
      client.update_preauth_hash(packet)
      expect(client.preauth_integrity_hash_value).to eq(hash)
    end
  end

  context 'Encryption' do
    describe '#smb3_encrypt' do
      let(:transform_packet) { double('TransformHeader packet') }
      let(:session_key) { "\x5c\x00\x4a\x3b\xf0\xa2\x4f\x75\x4c\xb2\x74\x0a\xcf\xc4\x8e\x1a".b }
      let(:data) { RubySMB::SMB2::Packet::TreeConnectRequest.new.to_binary_s }

      before :example do
        allow(RubySMB::SMB2::Packet::TransformHeader).to receive(:new).and_return(transform_packet)
        allow(transform_packet).to receive(:encrypt)
        client.session_key = session_key
      end

      it 'does not generate a new client encryption key if it already exists' do
        client.client_encryption_key = 'key'
        expect(RubySMB::Crypto::KDF).to_not receive(:counter_mode)
        expect(client.client_encryption_key).to eq('key')
        client.smb3_encrypt(data)
      end

      ['0x0300', '0x0302'].each do |dialect|
        context "with #{dialect} dialect" do
          before :example do
            client.dialect = dialect
          end

          it 'generates the client encryption key with the expected parameters' do
            expect(RubySMB::Crypto::KDF).to receive(:counter_mode).with(
              session_key,
              "SMB2AESCCM\x00",
              "ServerIn \x00"
            ).and_call_original
            client.smb3_encrypt(data)
          end
        end
      end

      context 'with 0x0311 dialect' do
        it 'generates the client encryption key with the expected parameters' do
          client.preauth_integrity_hash_value = ''
          client.dialect = '0x0311'
          expect(RubySMB::Crypto::KDF).to receive(:counter_mode).with(
            session_key,
            "SMBC2SCipherKey\x00",
            ''
          ).and_call_original
          client.smb3_encrypt(data)
        end
      end

      it 'creates a TransformHeader packet and encrypt the data' do
        client.dialect = '0x0300'
        client.encryption_algorithm = 'AES-128-CCM'
        client.session_id = 123
        client.smb3_encrypt(data)
        expect(RubySMB::SMB2::Packet::TransformHeader).to have_received(:new).with(flags: 1, session_id: 123)
        expect(transform_packet).to have_received(:encrypt).with(data, client.client_encryption_key, algorithm: 'AES-128-CCM')
      end

      it 'generates the expected client encryption key with 0x0302 dialect' do
        client.dialect = '0x0302'
        expected_enc_key =
          "\xa4\xfa\x23\xc1\xb0\x65\x84\xce\x47\x08\x5b\xe0\x64\x98\xd7\x87".b
        client.smb3_encrypt(data)
        expect(client.client_encryption_key).to eq expected_enc_key
      end

      it 'generates the expected client encryption key with 0x0311 dialect' do
        client.dialect = '0x0311'
        client.session_key =
          "\x5c\x00\x4a\x3b\xf0\xa2\x4f\x75\x4c\xb2\x74\x0a\xcf\xc4\x8e\x1a".b
        client.preauth_integrity_hash_value =
          "\x57\x77\x7d\x47\xc2\xa9\xc8\x23\x6e\x8a\xfa\x39\xe8\x77\x2f\xb0\xb6"\
          "\x01\xba\x85\x58\x77\xf5\x01\xa0\xf0\x31\x69\x6a\x64\x49\x1c\x61\xdb"\
          "\x57\x34\x19\x1b\x80\x33\x9a\xfa\x1d\x6c\x3f\xca\x44\x68\x78\x5b\xb9"\
          "\xda\x41\xfa\x83\xe5\xa9\x6f\xcf\x44\xbc\xe5\x26\x6e".b
        expected_enc_key =
          "\xc7\x4e\xfe\x4d\x15\x48\x5b\x0b\x71\x45\x49\x26\x8a\xd9\x6c\xaa".b
        client.smb3_encrypt(data)
        expect(client.client_encryption_key).to eq expected_enc_key
      end
    end

    describe '#smb3_decrypt' do
      let(:transform_packet) { double('TransformHeader packet') }
      let(:session_key) { "\x5c\x00\x4a\x3b\xf0\xa2\x4f\x75\x4c\xb2\x74\x0a\xcf\xc4\x8e\x1a".b }

      before :example do
        allow(transform_packet).to receive(:decrypt)
        client.session_key = session_key
      end

      it 'does not generate a new server encryption key if it already exists' do
        client.server_encryption_key = 'key'
        expect(RubySMB::Crypto::KDF).to_not receive(:counter_mode)
        expect(client.server_encryption_key).to eq('key')
        client.smb3_decrypt(transform_packet)
      end

      ['0x0300', '0x0302'].each do |dialect|
        context "with #{dialect} dialect" do
          before :example do
            client.dialect = dialect
          end

          it 'generates the client encryption key with the expected parameters' do
            expect(RubySMB::Crypto::KDF).to receive(:counter_mode).with(
              session_key,
              "SMB2AESCCM\x00",
              "ServerOut\x00"
            ).and_call_original
            client.smb3_decrypt(transform_packet)
          end
        end
      end

      context 'with 0x0311 dialect' do
        it 'generates the client encryption key with the expected parameters' do
          client.preauth_integrity_hash_value = ''
          client.dialect = '0x0311'
          expect(RubySMB::Crypto::KDF).to receive(:counter_mode).with(
            session_key,
            "SMBS2CCipherKey\x00",
            ''
          ).and_call_original
          client.smb3_decrypt(transform_packet)
        end
      end

      it 'creates a TransformHeader packet and encrypt the data' do
        client.dialect = '0x0300'
        client.encryption_algorithm = 'AES-128-CCM'
        client.session_id = 123
        client.smb3_decrypt(transform_packet)
        expect(transform_packet).to have_received(:decrypt).with(client.server_encryption_key, algorithm: 'AES-128-CCM')
      end

      it 'generates the expected server encryption key with 0x0302 dialect' do
        client.dialect = '0x0302'
        expected_enc_key =
          "\x65\x21\xd3\x6d\xe9\xe3\x5a\x66\x09\x61\xae\x3e\xc6\x49\x6b\xdf".b
        client.smb3_decrypt(transform_packet)
        expect(client.server_encryption_key).to eq expected_enc_key
      end

      it 'generates the expected server encryption key with 0x0311 dialect' do
        client.dialect = '0x0311'
        client.session_key =
          "\x5c\x00\x4a\x3b\xf0\xa2\x4f\x75\x4c\xb2\x74\x0a\xcf\xc4\x8e\x1a".b
        client.preauth_integrity_hash_value =
          "\x57\x77\x7d\x47\xc2\xa9\xc8\x23\x6e\x8a\xfa\x39\xe8\x77\x2f\xb0\xb6"\
          "\x01\xba\x85\x58\x77\xf5\x01\xa0\xf0\x31\x69\x6a\x64\x49\x1c\x61\xdb"\
          "\x57\x34\x19\x1b\x80\x33\x9a\xfa\x1d\x6c\x3f\xca\x44\x68\x78\x5b\xb9"\
          "\xda\x41\xfa\x83\xe5\xa9\x6f\xcf\x44\xbc\xe5\x26\x6e".b
        expected_enc_key =
          "\x8c\x2c\x31\x15\x66\xba\xa9\xab\xcf\xb2\x47\x8d\x72\xd5\xd7\x4a".b
        client.smb3_decrypt(transform_packet)
        expect(client.server_encryption_key).to eq expected_enc_key
      end
    end
  end
end

