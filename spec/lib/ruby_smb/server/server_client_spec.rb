RSpec.describe RubySMB::Server::ServerClient do
  let(:server) { RubySMB::Server.new(server_sock: ::TCPServer.new(0)) }
  let(:sock) { double('Socket', peeraddr: '192.168.1.5') }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(sock) }
  subject(:server_client) { described_class.new(server, dispatcher) }

  it { is_expected.to respond_to :dialect }
  it { is_expected.to respond_to :identity }
  it { is_expected.to respond_to :state }
  it { is_expected.to respond_to :session_key }

  describe '#disconnect!' do
    it 'closes the socket' do
      expect(dispatcher.tcp_socket).to receive(:close).with(no_args).and_return(nil)
      server_client.disconnect!
    end
  end

  describe '#initialize' do
    it 'starts in the negotiate state' do
      expect(server_client.state).to eq :negotiate
    end

    it 'starts without a dialect' do
      expect(server_client.dialect).to be_nil
      expect(server_client.metadialect).to be_nil
    end

    it 'starts without an identity' do
      expect(server_client.identity).to be_nil
    end

    it 'starts without a session_key' do
      expect(server_client.session_key).to be_nil
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
      expect(dispatcher.tcp_socket).to receive(:closed?).and_return(true)
    end

    it 'calls #handle_negotiate when the state is negotiate' do
      expect(server_client).to receive(:handle_negotiate).with(packet).and_return(nil)
      server_client.instance_eval { @state = :negotiate }
      server_client.run
    end

    it 'calls #handle_session_setup when the state is session_setup' do
      expect(server_client).to receive(:handle_session_setup).with(packet).and_return(nil)
      server_client.instance_eval { @state = :session_setup }
      server_client.run
    end

    it 'calls #authenticated when the state is authenticated' do
      expect(server_client).to receive(:handle_authenticated).with(packet).and_return(nil)
      server_client.instance_eval { @state = :authenticated }
      server_client.run
    end
  end

  describe '#send_packet' do
    let(:packet) { RubySMB::GenericPacket.new }

    before(:each) do
      expect(dispatcher).to receive(:send_packet).with(packet).and_return(nil)
    end

    it 'sends a packet to the dispatcher' do
      server_client.send_packet(packet)
    end

    %w{ 0x0202 0x0210 0x0300 0x0302 0x0311 }.each do |dialect|
      context "when the dialect is #{dialect}" do
        before(:each) do
          server_client.instance_eval { @dialect = dialect }
        end

        context 'and the state is authenticated' do
          before(:each) do
            server_client.instance_eval { @state = :authenticated }
          end

          context 'and the identity is anonymous' do
            before(:each) do
              server_client.instance_eval { @identity = RubySMB::Gss::Provider::IDENTITY_ANONYMOUS }
            end

            it 'does not sign packets' do
              expect(server_client).to_not receive(:smb2_sign)
              expect(server_client).to_not receive(:smb3_sign)
              server_client.send_packet(packet)
            end
          end

          context 'and the identity is not anonymous' do
            before(:each) do
              server_client.instance_eval { @identity = 'WORKGROUP\RubySMB'; @session_key = Random.new.bytes(16) }
            end

            it 'does sign packets' do
              packet = RubySMB::GenericPacket.new
              dialect_family = RubySMB::Dialect[dialect].family
              if dialect_family == RubySMB::Dialect::FAMILY_SMB2
                expect(server_client).to receive(:smb2_sign).with(packet).and_return(packet)
                expect(server_client).to_not receive(:smb3_sign)
              elsif dialect_family == RubySMB::Dialect::FAMILY_SMB3
                expect(server_client).to receive(:smb3_sign).with(packet).and_return(packet)
                expect(server_client).to_not receive(:smb2_sign)
              end
              server_client.send_packet(packet)
            end
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
