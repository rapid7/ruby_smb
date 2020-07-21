RSpec.describe RubySMB::SMB2::Pipe do

  let(:sock) { double('Socket', peeraddr: '192.168.1.5') }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(sock) }

  let(:client) { RubySMB::Client.new(dispatcher, username: 'msfadmin', password: 'msfadmin') }
  let(:tree_id) { 2049 }
  let(:path) { '\\192.168.1.1\IPC$' }
  let(:connect_response) {
    packet = RubySMB::SMB2::Packet::TreeConnectResponse.new
    packet.smb2_header.tree_id = tree_id
    packet.maximal_access.read("\xff\x01\x1f\x00")
    packet.share_type = 0x01
    packet
  }

  let(:tree) { RubySMB::SMB2::Tree.new(client: client, share: path, response: connect_response) }
  let(:file_id) { RubySMB::Field::Smb2Fileid.read('\x6d\x01\x00\x00\x00\x00\x00\x00\x\x01\x00\x00\x00\xff\xff\xff\xff') }
  let(:time) { DateTime.now }
  let(:create_response) {
    RubySMB::SMB2::Packet::CreateResponse.new(
      file_id: file_id,
      end_of_file: 108,
      allocation_size: 112,
      last_access: time,
      last_change: time,
      last_write: time
    )
  }
  let(:ioctl_response) {
    packet = RubySMB::SMB2::Packet::IoctlResponse.new
    packet.buffer = "\x03\x00\x00\x00" + "\x10\x20\x30\x40" + "\x00\x00\x00\x00" + "\x00\x00\x00\x00"
    packet
  }
  let(:filename) { 'msf-pipe' }

  subject(:pipe) { described_class.new(name: filename, response: create_response, tree: tree) }

  describe '#peek' do
    let(:request) { RubySMB::SMB2::Packet::IoctlRequest.new }
    let(:raw_response) { double('Raw response') }
    let(:response) { double('Response') }

    before :example do
      allow(RubySMB::SMB2::Packet::IoctlRequest).to receive(:new).and_return(request)
      allow(client).to receive(:send_recv).and_return(raw_response)
      allow(RubySMB::SMB2::Packet::IoctlResponse).to receive(:read).and_return(response)
      allow(response).to receive(:valid?).and_return(true)
      allow(response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_SUCCESS)
    end

    it 'creates a IoctlRequest'do
      expect(RubySMB::SMB2::Packet::IoctlRequest).to receive(:new)
      pipe.peek
    end

    it 'sets the request #ctl_code field' do
      expect(request).to receive(:ctl_code=).with(RubySMB::Fscc::ControlCodes::FSCTL_PIPE_PEEK)
      pipe.peek
    end

    it 'sets the request #is_fsctl flag to true' do
      pipe.peek
      expect(request.flags.is_fsctl).to eq 1
    end

    it 'sets the request #max_output_response field to the expected value' do
      pipe.peek(peek_size: 10)
      expect(request.max_output_response).to eq(16 + 10)
    end

    it 'calls #set_header_fields' do
      expect(pipe).to receive(:set_header_fields).with(request)
      pipe.peek
    end

    it 'calls Client #send_recv' do
      expect(client).to receive(:send_recv).with(request)
      pipe.peek
    end

    it 'parses the response as a SMB2 IoctlResponse packet' do
      expect(RubySMB::SMB2::Packet::IoctlResponse).to receive(:read).with(raw_response)
      pipe.peek
    end

    it 'raises an InvalidPacket exception if the response is not valid' do
      allow(response).to receive(:valid?).and_return(false)
      smb2_header = double('SMB2 Header')
      allow(response).to receive(:smb2_header).and_return(smb2_header)
      allow(smb2_header).to receive_messages(:protocol => nil, :command => nil)
      expect { pipe.peek }.to raise_error(RubySMB::Error::InvalidPacket)
    end

    it 'raises an UnexpectedStatusCode exception if the response status code is not STATUS_SUCCESS or STATUS_BUFFER_OVERFLOW' do
      allow(response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_OBJECT_NAME_NOT_FOUND)
      expect { pipe.peek }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
    end

    it 'returns the expected response' do
      expect(pipe.peek).to eq(response)
    end
  end

  describe '#peek_available' do
    it 'reads the correct number of bytes available' do
      allow(pipe).to receive(:peek) { ioctl_response }
      allow(pipe).to receive(:peek_available) { pipe.peek.buffer.unpack('VV')[1] }
      expect(pipe.peek_available).to eq(0x40302010)
    end
  end

  describe '#peek_state' do
    it 'reads the correct state of the pipe' do
      allow(pipe).to receive(:peek) { ioctl_response }
      allow(pipe).to receive(:peek_state)  { pipe.peek.buffer.unpack('V')[0] }
      expect(pipe.peek_state).to eq(RubySMB::SMB2::Pipe::STATUS_CONNECTED)
    end
  end

  describe '#is_connected?' do
    it 'identifies that the pipe is connected from the status' do
      allow(pipe).to receive(:peek) { ioctl_response }
      allow(pipe).to receive(:peek_state)  { pipe.peek.buffer.unpack('V')[0] }
      allow(pipe).to receive(:is_connected?) { pipe.peek_state == RubySMB::SMB2::Pipe::STATUS_CONNECTED }
      expect(pipe.is_connected?).to eq(true)
    end
  end

  describe '#initialize' do
    context 'when name is not provided' do
      it 'raises an ArgumentError' do
        expect {
          described_class.new(tree: tree, response: create_response, name: nil)
        }.to raise_error(ArgumentError)
      end
    end

    it 'calls the superclass with the expected arguments' do
      expect(pipe.tree).to eq(tree)
      expect(pipe.name).to eq(filename)
      expect(pipe.attributes).to eq(create_response.file_attributes)
      expect(pipe.guid).to eq(create_response.file_id)
      expect(pipe.last_access).to eq(create_response.last_access.to_datetime)
      expect(pipe.last_change).to eq(create_response.last_change.to_datetime)
      expect(pipe.last_write).to eq(create_response.last_write.to_datetime)
      expect(pipe.size).to eq(create_response.end_of_file)
      expect(pipe.size_on_disk).to eq(create_response.allocation_size)
    end

    context 'with \'srvsvc\' filename' do
      it 'extends Srvsvc class' do
        pipe = described_class.new(tree: tree, response: create_response, name: 'srvsvc')
        expect(pipe.respond_to?(:net_share_enum_all)).to be true
      end
    end

    context 'with \'winreg\' filename' do
      it 'extends Winreg class' do
        pipe = described_class.new(tree: tree, response: create_response, name: 'winreg')
        expect(pipe.respond_to?(:has_registry_key?)).to be true
      end
    end

    context 'with \'svcctl\' filename' do
      it 'extends svcctl class' do
        pipe = described_class.new(tree: tree, response: create_response, name: 'svcctl')
        expect(pipe.respond_to?(:query_service_config)).to be true
      end
    end
  end

  describe '#dcerpc_request' do
    let(:options) { { host: '1.2.3.4' } }
    let(:stub_packet ) { RubySMB::Dcerpc::Winreg::OpenKeyRequest.new }
    let(:dcerpc_request) { double('DCERPC Request') }
    let(:request_stub) { double('Request stub') }
    before :example do
      allow(RubySMB::Dcerpc::Request).to receive(:new).and_return(dcerpc_request)
      allow(dcerpc_request).to receive(:stub).and_return(request_stub)
      allow(request_stub).to receive(:read)
      allow(pipe).to receive(:ioctl_send_recv)
    end

    it 'creates a Request packet with the expected arguments' do
      pipe.dcerpc_request(stub_packet, options)
      expect(options).to eq( { host: '1.2.3.4', endpoint: 'Winreg' })
      expect(RubySMB::Dcerpc::Request).to have_received(:new).with({ opnum: stub_packet.opnum }, options)
    end

    it 'sets DCERPC request stub to the stub packet passed as argument' do
      pipe.dcerpc_request(stub_packet, options)
      expect(request_stub).to have_received(:read).with(stub_packet.to_binary_s)
    end

    it 'calls #ioctl_send_recv with the expected arguments' do
      pipe.dcerpc_request(stub_packet, options)
      expect(pipe).to have_received(:ioctl_send_recv).with(dcerpc_request, options)
    end
  end

  describe '#ioctl_send_recv' do
    let(:ioctl_request_packet) { double('IoctlRequest') }
    let(:flags) { double('Flags') }
    let(:dcerpc_request) { double('DCERPC Request') }
    let(:binary_dcerpc_request)     { double('Binary DCERPC Request') }
    let(:options) { { host: '1.2.3.4' } }
    let(:ioctl_raw_response)     { double('IOCTL raw response') }
    let(:ioctl_response)     { double('IOCTL response') }
    let(:raw_data)                  { double('Raw data') }
    let(:dcerpc_response)           { double('DCERPC Response') }
    let(:result)                    { 'Result' }
    before :example do
      allow(RubySMB::SMB2::Packet::IoctlRequest).to receive(:new).and_return(ioctl_request_packet)
      allow(pipe).to receive(:set_header_fields).and_return(ioctl_request_packet)
      allow(ioctl_request_packet).to receive_messages(
        :ctl_code= => nil,
        :flags     => flags,
        :buffer=   => nil
      )
      allow(flags).to receive(:is_fsctl=)
      allow(dcerpc_request).to receive(:to_binary_s).and_return(binary_dcerpc_request)
      allow(client).to receive(:send_recv).and_return(ioctl_raw_response)
      allow(RubySMB::SMB2::Packet::IoctlResponse).to receive(:read).and_return(ioctl_response)
      allow(ioctl_response).to receive_messages(
        :valid? => true,
        :status_code => WindowsError::NTStatus::STATUS_SUCCESS,
        :output_data => raw_data
      )
      allow(RubySMB::Dcerpc::Response).to receive(:read).and_return(dcerpc_response)
      allow(dcerpc_response).to receive_message_chain(:pdu_header, :ptype => RubySMB::Dcerpc::PTypes::RESPONSE)
      allow(dcerpc_response).to receive(:stub).and_return(result)
    end

    it 'creates an IoctlRequest packet' do
      pipe.ioctl_send_recv(dcerpc_request, options)
      expect(RubySMB::SMB2::Packet::IoctlRequest).to have_received(:new).with(options)
    end

    it 'calls #set_header_fields' do
      pipe.ioctl_send_recv(dcerpc_request, options)
      expect(pipe).to have_received(:set_header_fields).with(ioctl_request_packet)
    end

    it 'sets the expected properties on the request packet' do
      pipe.ioctl_send_recv(dcerpc_request, options)
      expect(ioctl_request_packet).to have_received(:ctl_code=).with(0x11C017)
      expect(flags).to have_received(:is_fsctl=).with(0x1)
      expect(ioctl_request_packet).to have_received(:buffer=).with(binary_dcerpc_request)
    end

    it 'sends the expected request' do
      pipe.ioctl_send_recv(dcerpc_request, options)
      expect(client).to have_received(:send_recv).with(ioctl_request_packet)
    end

    it 'creates an IoctlResponse packet from the response' do
      pipe.ioctl_send_recv(dcerpc_request, options)
      expect(RubySMB::SMB2::Packet::IoctlResponse).to have_received(:read).with(ioctl_raw_response)
    end

    context 'when the response is not an IoctlResponse packet' do
      it 'raises an InvalidPacket exception' do
        allow(ioctl_response).to receive_message_chain(:smb2_header, :protocol)
        allow(ioctl_response).to receive_message_chain(:smb2_header, :command)
        allow(ioctl_response).to receive(:valid?).and_return(false)
        expect { pipe.ioctl_send_recv(dcerpc_request, options) }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end

    context 'when the response status code is not STATUS_SUCCESS or STATUS_BUFFER_OVERFLOW' do
      it 'raises an UnexpectedStatusCode exception' do
        allow(ioctl_response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_INVALID_HANDLE)
        expect { pipe.ioctl_send_recv(dcerpc_request, options) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
      end
    end

    context 'when the response status code is STATUS_SUCCESS' do
      it 'does not raise any exception' do
        expect { pipe.ioctl_send_recv(dcerpc_request, options)}.not_to raise_error
      end

      it 'creates a DCERPC Response packet from the response' do
        pipe.ioctl_send_recv(dcerpc_request, options)
        expect(RubySMB::Dcerpc::Response).to have_received(:read).with(raw_data)
      end

      context 'when an IOError occurs while parsing the DCERPC response' do
        it 'raises an InvalidPacket exception' do
          allow(RubySMB::Dcerpc::Response).to receive(:read).and_raise(IOError)
          expect { pipe.ioctl_send_recv(dcerpc_request, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
        end
      end

      context 'when the response is not a DCERPC Response packet' do
        it 'raises an InvalidPacket exception' do
          allow(dcerpc_response).to receive_message_chain(:pdu_header, :ptype => RubySMB::Dcerpc::PTypes::FAULT)
          expect { pipe.ioctl_send_recv(dcerpc_request, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
        end
      end

      it 'returns the expected stub data' do
        expect(pipe.ioctl_send_recv(dcerpc_request, options)).to eq(result)
      end
    end

    context 'when the response status code is STATUS_BUFFER_OVERFLOW' do
      let(:data_count) { 100 }
      let(:added_raw_data) { double('Added raw data') }
      before :example do
        allow(ioctl_response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_BUFFER_OVERFLOW)
        allow(ioctl_response).to receive(:output_count).and_return(data_count)
        allow(pipe).to receive(:read).and_return(added_raw_data)
        allow(raw_data).to receive(:<<)
        allow(dcerpc_response).to receive_message_chain(:pdu_header, :pfc_flags, :first_frag => 1)
        allow(dcerpc_response).to receive_message_chain(:pdu_header, :pfc_flags, :last_frag => 1)
      end

      it 'does not raise any exception' do
        expect { pipe.ioctl_send_recv(dcerpc_request, options) }.not_to raise_error
      end

      it 'reads the expected number of bytes and concatenate it the first response raw data' do
        pipe.ioctl_send_recv(dcerpc_request, options)
        expect(pipe).to have_received(:read).with(bytes: tree.client.max_buffer_size - data_count)
        expect(raw_data).to have_received(:<<).with(added_raw_data)
      end

      it 'creates a DCERPC Response packet from the updated raw data' do
        pipe.ioctl_send_recv(dcerpc_request, options)
        expect(RubySMB::Dcerpc::Response).to have_received(:read).with(raw_data)
      end

      context 'when an IOError occurs while parsing the DCERPC response' do
        it 'raises an InvalidPacket exception' do
          allow(RubySMB::Dcerpc::Response).to receive(:read).and_raise(IOError)
          expect { pipe.ioctl_send_recv(dcerpc_request, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
        end
      end

      context 'when the response is not a DCERPC Response packet' do
        it 'raises an InvalidPacket exception' do
          allow(dcerpc_response).to receive_message_chain(:pdu_header, :ptype => RubySMB::Dcerpc::PTypes::FAULT)
          expect { pipe.ioctl_send_recv(dcerpc_request, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
        end
      end

      context 'when the response is not the first fragment' do
        it 'raises an InvalidPacket exception' do
          allow(dcerpc_response).to receive_message_chain(:pdu_header, :pfc_flags, :first_frag => 0)
          expect { pipe.ioctl_send_recv(dcerpc_request, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
        end
      end

      context 'when the response is the last fragment' do
        it 'only reads the pipe once' do
          pipe.ioctl_send_recv(dcerpc_request, options)
          expect(RubySMB::Dcerpc::Response).to have_received(:read).once
        end

        it 'returns the expected stub data' do
          expect(pipe.ioctl_send_recv(dcerpc_request, options)).to eq(result)
        end
      end

      context 'when the response is not the last fragment' do
        let(:raw_data2)        { double('Raw data #2') }
        let(:dcerpc_response2) { double('DCERPC Response #2') }
        let(:result2)          { 'Result #2' }
        before :example do
          allow(dcerpc_response).to receive_message_chain(:pdu_header, :pfc_flags, :last_frag => 0)
          allow(pipe).to receive(:read).with(bytes: tree.client.max_buffer_size).and_return(raw_data2)
          allow(RubySMB::Dcerpc::Response).to receive(:read).with(raw_data2).and_return(dcerpc_response2)
          allow(dcerpc_response2).to receive_message_chain(:pdu_header, :ptype => RubySMB::Dcerpc::PTypes::RESPONSE)
          allow(dcerpc_response2).to receive_message_chain(:pdu_header, :pfc_flags, :last_frag => 1)
          allow(dcerpc_response2).to receive(:stub).and_return(result2)
        end

        it 'reads the expected number of bytes' do
          pipe.ioctl_send_recv(dcerpc_request, options)
          expect(pipe).to have_received(:read).with(bytes: tree.client.max_buffer_size)
        end

        it 'creates a DCERPC Response packet from the new raw data' do
          pipe.ioctl_send_recv(dcerpc_request, options)
          expect(RubySMB::Dcerpc::Response).to have_received(:read).with(raw_data2)
        end

        context 'when an IOError occurs while parsing the new DCERPC response' do
          it 'raises an InvalidPacket exception' do
            allow(RubySMB::Dcerpc::Response).to receive(:read).with(raw_data2).and_raise(IOError)
            expect { pipe.ioctl_send_recv(dcerpc_request, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
          end
        end

        context 'when the new response is not a DCERPC Response packet' do
          it 'raises an InvalidPacket exception' do
            allow(dcerpc_response2).to receive_message_chain(:pdu_header, :ptype => RubySMB::Dcerpc::PTypes::FAULT)
            expect { pipe.ioctl_send_recv(dcerpc_request, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
          end
        end

        it 'returns the expected stub data' do
          expect(pipe.ioctl_send_recv(dcerpc_request, options)).to eq(result)
        end
      end
    end
  end

end
