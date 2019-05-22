RSpec.describe RubySMB::SMB1::Pipe do

  it { expect(described_class).to be < RubySMB::SMB1::File }

  let(:peek_nmpipe_response) {
    packet = RubySMB::SMB1::Packet::Trans::PeekNmpipeResponse.new
    packet.data_block.trans_parameters.read("\x10\x20\x00\x00\x03\x00")
    packet
  }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(double('socket')) }
  let(:client) { RubySMB::Client.new(dispatcher, username: 'msfadmin', password: 'msfadmin') }
  let(:connect_response) {
    packet = RubySMB::SMB1::Packet::TreeConnectResponse.new
    packet.smb_header.tid = 2051
    packet.parameter_block.guest_access_rights.read("\xff\x01\x1f\x00")
    packet.parameter_block.access_rights.read("\xff\x01\x1f\x01")
    packet
  }
  let(:tree) { RubySMB::SMB1::Tree.new(client: client, share: '\\1.2.3.4\IPC$', response: connect_response) }
  let(:nt_create_andx_response) {
    response = RubySMB::SMB1::Packet::NtCreateAndxResponse.new
    response.parameter_block.ext_file_attributes = { normal: 1 }
    response.parameter_block.fid = 0x4000
    response.parameter_block.last_access_time = DateTime.parse("2017-09-20T1:1:1")
    response.parameter_block.last_change_time = DateTime.parse("2017-09-22T2:2:2")
    response.parameter_block.last_write_time  = DateTime.parse("2017-09-25T3:3:3")
    response.parameter_block.end_of_file = 53
    response.parameter_block.allocation_size = 4096
    response
  }
  let(:filename) { 'msf-pipe' }

  subject(:pipe) {
    described_class.new(tree: tree, response: nt_create_andx_response, name: filename)
  }

  describe '#peek' do
    let(:request) { RubySMB::SMB1::Packet::Trans::PeekNmpipeRequest.new }
    let(:raw_response) { double('Raw response') }
    let(:response) { double('Response') }

    before :example do
      allow(RubySMB::SMB1::Packet::Trans::PeekNmpipeRequest).to receive(:new).and_return(request)
      allow(client).to receive(:send_recv).and_return(raw_response)
      allow(RubySMB::SMB1::Packet::Trans::PeekNmpipeResponse).to receive(:read).and_return(response)
      allow(response).to receive(:valid?).and_return(true)
      allow(response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_SUCCESS)
    end

    it 'creates a PeekNmpipeRequest'do
      expect(RubySMB::SMB1::Packet::Trans::PeekNmpipeRequest).to receive(:new)
      pipe.peek
    end

    it 'sets the request #fid field' do
      expect(request).to receive(:fid=).with(pipe.fid)
      pipe.peek
    end

    it 'sets the request #max_data_count fieldto the peek_size argument' do
      peek_size = 5
      pipe.peek(peek_size: peek_size)
      expect(request.parameter_block.max_data_count).to eq(peek_size)
    end

    it 'calls Tree #set_header_fields' do
      expect(tree).to receive(:set_header_fields).with(request)
      pipe.peek
    end

    it 'calls Client #send_recv' do
      expect(client).to receive(:send_recv).with(request)
      pipe.peek
    end

    it 'parses the response as a SMB1 PeekNmpipeResponse packet' do
      expect(RubySMB::SMB1::Packet::Trans::PeekNmpipeResponse).to receive(:read).with(raw_response)
      pipe.peek
    end

    it 'raises an InvalidPacket exception if the response is not valid' do
      allow(response).to receive(:valid?).and_return(false)
      smb_header = double('SMB Header')
      allow(response).to receive(:smb_header).and_return(smb_header)
      allow(smb_header).to receive_messages(:protocol => nil, :command => nil)
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
      allow(pipe).to receive(:peek) { peek_nmpipe_response }
      allow(pipe).to receive(:peek_available) { pipe.peek.data_block.trans_parameters.read_data_available }
      expect(pipe.peek_available).to eq(0x2010)
    end
  end

  describe '#peek_state' do
    it 'reads the correct state of the pipe' do
      allow(pipe).to receive(:peek) { peek_nmpipe_response }
      allow(pipe).to receive(:peek_state) { pipe.peek.data_block.trans_parameters.pipe_state }
      expect(pipe.peek_state).to eq(RubySMB::SMB1::Pipe::STATUS_OK)
    end
  end

  describe '#is_connected?' do
    it 'identifies that the pipe is connected from the status' do
      allow(pipe).to receive(:peek) { peek_nmpipe_response }
      allow(pipe).to receive(:peek_state) { pipe.peek.data_block.trans_parameters.pipe_state }
      allow(pipe).to receive(:is_connected?) { pipe.peek_state == RubySMB::SMB1::Pipe::STATUS_OK }
      expect(pipe.is_connected?).to eq(true)
    end
  end

  describe '#initialize' do
    context 'when name is not provided' do
      it 'raises an ArgumentError' do
        expect {
          described_class.new(tree: tree, response: nt_create_andx_response, name: nil)
        }.to raise_error(ArgumentError)
      end
    end

    it 'calls the superclass with the expected arguments' do
      expect(pipe.tree).to eq(tree)
      expect(pipe.name).to eq(filename)
      expect(pipe.attributes).to eq(nt_create_andx_response.parameter_block.ext_file_attributes)
      expect(pipe.fid).to eq(nt_create_andx_response.parameter_block.fid)
      expect(pipe.last_access).to eq(nt_create_andx_response.parameter_block.last_access_time.to_datetime)
      expect(pipe.last_change).to eq(nt_create_andx_response.parameter_block.last_change_time.to_datetime)
      expect(pipe.last_write).to eq(nt_create_andx_response.parameter_block.last_write_time.to_datetime)
      expect(pipe.size).to eq(nt_create_andx_response.parameter_block.end_of_file)
      expect(pipe.size_on_disk).to eq(nt_create_andx_response.parameter_block.allocation_size)
    end

    context 'with \'srvsvc\' filename' do
      it 'extends Srvsvc class' do
        pipe = described_class.new(tree: tree, response: nt_create_andx_response, name: 'srvsvc')
        expect(pipe.respond_to?(:net_share_enum_all)).to be true
      end
    end

    context 'with \'winreg\' filename' do
      it 'extends Winreg class' do
        pipe = described_class.new(tree: tree, response: nt_create_andx_response, name: 'winreg')
        expect(pipe.respond_to?(:has_registry_key?)).to be true
      end
    end
  end

  describe '#dcerpc_request' do
    let(:options)                   { { host: '1.2.3.4' } }
    let(:stub_packet )              { RubySMB::Dcerpc::Winreg::OpenKeyRequest.new }
    let(:dcerpc_request)            { double('DCERPC Request') }
    let(:request_stub)              { double('Request stub') }
    let(:binary_dcerpc_request)     { double('Binary DCERPC Request') }
    let(:trans_nmpipe_request)      { double('TransactNmpipeRequest') }
    let(:trans_data)                { double('Trans data') }
    let(:trans_nmpipe_raw_response) { double('Trans nmpipe raw response') }
    let(:trans_nmpipe_response)     { double('TransactNmpipeResponse') }
    let(:raw_data)                  { double('Raw data') }
    let(:dcerpc_response)           { double('DCERPC Response') }
    let(:result)                    { 'Result' }

    before :example do
      allow(RubySMB::Dcerpc::Request).to receive(:new).and_return(dcerpc_request)
      allow(dcerpc_request).to receive_messages(
        :stub        => request_stub,
        :to_binary_s => binary_dcerpc_request
      )
      allow(request_stub).to receive(:read)
      allow(RubySMB::SMB1::Packet::Trans::TransactNmpipeRequest).to receive(:new).and_return(trans_nmpipe_request)
      allow(tree).to receive(:set_header_fields)
      allow(trans_nmpipe_request).to receive_message_chain(:data_block, :trans_data => trans_data)
      allow(trans_nmpipe_request).to receive(:set_fid)
      allow(trans_data).to receive(:write_data=)
      allow(client).to receive(:send_recv).and_return(trans_nmpipe_raw_response)
      allow(RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse).to receive(:read).and_return(trans_nmpipe_response)
      allow(trans_nmpipe_response).to receive_messages(
        :valid?      => true,
        :status_code => WindowsError::NTStatus::STATUS_SUCCESS
      )
      allow(trans_nmpipe_response).to receive_message_chain(:data_block, :trans_data, :read_data, :to_binary_s => raw_data)
      allow(RubySMB::Dcerpc::Response).to receive(:read).and_return(dcerpc_response)
      allow(dcerpc_response).to receive_message_chain(:pdu_header, :ptype => RubySMB::Dcerpc::PTypes::RESPONSE)
      allow(dcerpc_response).to receive(:stub).and_return(result)
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

    it 'creates a Trans TransactNmpipeRequest packet' do
      pipe.dcerpc_request(stub_packet, options)
      expect(RubySMB::SMB1::Packet::Trans::TransactNmpipeRequest).to have_received(:new).with(options)
    end

    it 'calls Tree #set_header_fields' do
      pipe.dcerpc_request(stub_packet, options)
      expect(tree).to have_received(:set_header_fields).with(trans_nmpipe_request)
    end

    it 'calls TransactNmpipeRequest #set_fid' do
      pipe.dcerpc_request(stub_packet, options)
      expect(trans_nmpipe_request).to have_received(:set_fid).with(pipe.fid)
    end

    it 'sets the expected #write_data request property' do
      pipe.dcerpc_request(stub_packet, options)
      expect(trans_data).to have_received(:write_data=).with(binary_dcerpc_request)
    end

    it 'sends the expected request' do
      pipe.dcerpc_request(stub_packet, options)
      expect(client).to have_received(:send_recv).with(trans_nmpipe_request)
    end

    it 'creates a Trans TransactNmpipeResponse packet from the response' do
      pipe.dcerpc_request(stub_packet, options)
      expect(RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse).to have_received(:read).with(trans_nmpipe_raw_response)
    end

    context 'when the response is not a Trans packet' do
      it 'raises an InvalidPacket exception' do
        allow(trans_nmpipe_response).to receive_message_chain(:smb_header, :protocol)
        allow(trans_nmpipe_response).to receive_message_chain(:smb_header, :command)
        allow(trans_nmpipe_response).to receive(:valid?).and_return(false)
        expect { pipe.dcerpc_request(stub_packet, options) }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end

    context 'when the response status code is not STATUS_SUCCESS or STATUS_BUFFER_OVERFLOW' do
      it 'raises an UnexpectedStatusCode exception' do
        allow(trans_nmpipe_response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_INVALID_HANDLE)
        expect { pipe.dcerpc_request(stub_packet, options) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
      end
    end

    context 'when the response status code is STATUS_SUCCESS' do
      it 'does not raise any exception' do
        expect { pipe.dcerpc_request(stub_packet, options) }.not_to raise_error
      end

      it 'creates a DCERPC Response packet from the response' do
        pipe.dcerpc_request(stub_packet, options)
        expect(RubySMB::Dcerpc::Response).to have_received(:read).with(raw_data)
      end

      context 'when an IOError occurs while parsing the DCERPC response' do
        it 'raises an InvalidPacket exception' do
          allow(RubySMB::Dcerpc::Response).to receive(:read).and_raise(IOError)
          expect { pipe.dcerpc_request(stub_packet, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
        end
      end

      context 'when the response is not a DCERPC Response packet' do
        it 'raises an InvalidPacket exception' do
          allow(dcerpc_response).to receive_message_chain(:pdu_header, :ptype => RubySMB::Dcerpc::PTypes::FAULT)
          expect { pipe.dcerpc_request(stub_packet, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
        end
      end

      it 'returns the expected stub data' do
        expect(pipe.dcerpc_request(stub_packet, options)).to eq(result)
      end
    end

    context 'when the response status code is STATUS_BUFFER_OVERFLOW' do
      let(:data_count)     { 100 }
      let(:added_raw_data) { double('Added raw data') }
      before :example do
        allow(trans_nmpipe_response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_BUFFER_OVERFLOW)
        allow(trans_nmpipe_response).to receive_message_chain(:parameter_block, :data_count => data_count)
        allow(pipe).to receive(:read).and_return(added_raw_data)
        allow(raw_data).to receive(:<<)
        allow(dcerpc_response).to receive_message_chain(:pdu_header, :pfc_flags, :first_frag => 1)
        allow(dcerpc_response).to receive_message_chain(:pdu_header, :pfc_flags, :last_frag => 1)
      end

      it 'does not raise any exception' do
        expect { pipe.dcerpc_request(stub_packet, options) }.not_to raise_error
      end

      it 'reads the expected number of bytes and concatenate it the first response raw data' do
        pipe.dcerpc_request(stub_packet, options)
        expect(pipe).to have_received(:read).with(bytes: tree.client.max_buffer_size - data_count)
        expect(raw_data).to have_received(:<<).with(added_raw_data)
      end

      it 'creates a DCERPC Response packet from the updated raw data' do
        pipe.dcerpc_request(stub_packet, options)
        expect(RubySMB::Dcerpc::Response).to have_received(:read).with(raw_data)
      end

      context 'when an IOError occurs while parsing the DCERPC response' do
        it 'raises an InvalidPacket exception' do
          allow(RubySMB::Dcerpc::Response).to receive(:read).and_raise(IOError)
          expect { pipe.dcerpc_request(stub_packet, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
        end
      end

      context 'when the response is not a DCERPC Response packet' do
        it 'raises an InvalidPacket exception' do
          allow(dcerpc_response).to receive_message_chain(:pdu_header, :ptype => RubySMB::Dcerpc::PTypes::FAULT)
          expect { pipe.dcerpc_request(stub_packet, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
        end
      end

      context 'when the response is not the first fragment' do
        it 'raises an InvalidPacket exception' do
          allow(dcerpc_response).to receive_message_chain(:pdu_header, :pfc_flags, :first_frag => 0)
          expect { pipe.dcerpc_request(stub_packet, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
        end
      end

      context 'when the response is the last fragment' do
        it 'only reads the pipe once' do
          pipe.dcerpc_request(stub_packet, options)
          expect(RubySMB::Dcerpc::Response).to have_received(:read).once
        end

        it 'returns the expected stub data' do
          expect(pipe.dcerpc_request(stub_packet, options)).to eq(result)
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
          pipe.dcerpc_request(stub_packet, options)
          expect(pipe).to have_received(:read).with(bytes: tree.client.max_buffer_size)
        end

        it 'creates a DCERPC Response packet from the new raw data' do
          pipe.dcerpc_request(stub_packet, options)
          expect(RubySMB::Dcerpc::Response).to have_received(:read).with(raw_data2)
        end

        context 'when an IOError occurs while parsing the new DCERPC response' do
          it 'raises an InvalidPacket exception' do
            allow(RubySMB::Dcerpc::Response).to receive(:read).with(raw_data2).and_raise(IOError)
            expect { pipe.dcerpc_request(stub_packet, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
          end
        end

        context 'when the new response is not a DCERPC Response packet' do
          it 'raises an InvalidPacket exception' do
            allow(dcerpc_response2).to receive_message_chain(:pdu_header, :ptype => RubySMB::Dcerpc::PTypes::FAULT)
            expect { pipe.dcerpc_request(stub_packet, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
          end
        end

        it 'returns the expected stub data' do
          expect(pipe.dcerpc_request(stub_packet, options)).to eq(result)
        end
      end
    end
  end
end
