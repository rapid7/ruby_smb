RSpec.describe RubySMB::Server::ServerClient do
  let(:server) { RubySMB::Server.new(server_sock: ::TCPServer.new(0)) }
  let(:sock) { double('Socket', peeraddr: '192.168.1.5') }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(sock) }
  subject(:server_client) { described_class.new(server, dispatcher) }

  it { is_expected.to respond_to :dialect }
  it { is_expected.to respond_to :session_table }

  describe '#disconnect!' do
    it 'closes the socket' do
      expect(dispatcher.tcp_socket).to receive(:closed?).with(no_args).and_return(false)
      expect(dispatcher.tcp_socket).to receive(:close).with(no_args).and_return(nil)
      server_client.disconnect!
    end
  end

  describe '#initialize' do
    it 'starts without a dialect' do
      expect(server_client.dialect).to be_nil
      expect(server_client.metadialect).to be_nil
    end

    it 'starts without any sessions' do
      expect(server_client.session_table).to be_empty
    end

    it 'creates a new authenticator instance' do
      expect(server.gss_provider).to receive(:new_authenticator).and_call_original
      described_class.new(server, dispatcher)
    end
  end

  describe '#process_gss' do
    before(:each) do
      expect(server_client.instance_eval { @gss_authenticator }).to receive(:process).and_call_original
    end

    it 'should handle an empty GSS buffer' do
      result = server_client.process_gss
      expect(result).to be_a RubySMB::Gss::Provider::Result
      expect(result.nt_status).to eq WindowsError::NTStatus::STATUS_SUCCESS
      expect(result.buffer).to_not be_empty
      expect(result.identity).to be_nil
    end
  end

  describe '#recv_packet' do
    it 'receives a new packet from the dispatcher' do
      expect(dispatcher).to receive(:recv_packet).with(no_args)
      server_client.recv_packet
    end
  end

  describe '#run' do
    let(:packet) { Random.new.bytes(16) }
    before(:each) do
      expect(server_client).to receive(:recv_packet).and_return(packet)
      # this hook should ensure that the dispatcher loop returns after processing a single request
      expect(dispatcher.tcp_socket).to receive(:closed?).with(no_args).and_return(true)
      expect(server_client).to receive(:disconnect!).with(no_args).and_return(nil)
    end

    it 'calls #handle_negotiate when the dialect is nil' do
      expect(server_client).to receive(:handle_negotiate).with(packet).and_return(nil)
      server_client.instance_eval { @dialect = nil }
      server_client.run
    end

    it 'calls #handle_smb when the dialect is not nil' do
      expect(server_client).to receive(:handle_smb).with(packet).and_return(nil)
      server_client.instance_eval { @dialect = true }
      server_client.run
    end
  end

  describe '#send_packet' do
    let(:session_id) { rand(0xffffffff) }
    let(:packet) { RubySMB::SMB2::Packet::SessionSetupResponse.new(smb2_header: { session_id: session_id }) }

    before(:each) do
      expect(dispatcher).to receive(:send_packet).with(packet).and_return(nil)
      server_client.session_table[session_id] = RubySMB::Server::Session.new(session_id)
    end

    it 'sends a packet to the dispatcher' do
      server_client.send_packet(packet)
    end

    %w{ 0x0202 0x0210 0x0300 0x0302 0x0311 }.each do |dialect|
      context "when the dialect is #{dialect}" do
        before(:each) do
          server_client.instance_eval { @dialect = dialect }
        end

        context 'and the identity is anonymous' do
          before(:each) do
            server_client.session_table[session_id].user_id = RubySMB::Gss::Provider::IDENTITY_ANONYMOUS
          end

          it 'does not sign packets' do
            expect(RubySMB::Signing).to_not receive(:smb2_sign)
            expect(RubySMB::Signing).to_not receive(:smb3_sign)
            server_client.send_packet(packet)
          end
        end

        context 'and the identity is not anonymous' do
          before(:each) do
            server_client.session_table[session_id].user_id = 'WORKGROUP\RubySMB'
            server_client.session_table[session_id].key = Random.new.bytes(16)
          end

          it 'does sign packets' do
            dialect_family = RubySMB::Dialect[dialect].family
            session = server_client.session_table[session_id]
            if dialect_family == RubySMB::Dialect::FAMILY_SMB2
              expect(RubySMB::Signing).to receive(:smb2_sign).with(packet, session.key).and_return(packet)
              expect(RubySMB::Signing).to_not receive(:smb3_sign)
            elsif dialect_family == RubySMB::Dialect::FAMILY_SMB3
              expect(RubySMB::Signing).to receive(:smb3_sign).with(packet, session.key, dialect, any_args).and_return(packet)
              expect(RubySMB::Signing).to_not receive(:smb2_sign)
            end
            server_client.send_packet(packet)
          end
        end
      end
    end
  end

  describe '#update_preauth_hash' do
    it 'raises an EncryptionError exception if the preauth integrity hash algorithm is not known' do
      expect { server_client.update_preauth_hash('Test') }.to raise_error(
        RubySMB::Error::EncryptionError,
        'Cannot compute the Preauth Integrity Hash value: Preauth Integrity Hash Algorithm is nil'
      )
    end
  end
end
