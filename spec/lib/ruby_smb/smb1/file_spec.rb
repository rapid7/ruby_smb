RSpec.describe RubySMB::SMB1::File do

  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(double('socket')) }
  let(:client) { RubySMB::Client.new(dispatcher, username: 'msfadmin', password: 'msfadmin') }
  let(:connect_response) {
    packet = RubySMB::SMB1::Packet::TreeConnectResponse.new
    packet.smb_header.tid = 2051
    packet.parameter_block.guest_access_rights.read("\xff\x01\x1f\x00")
    packet.parameter_block.access_rights.read("\xff\x01\x1f\x01")
    packet
  }
  let(:tree) { RubySMB::SMB1::Tree.new(client: client, share: '\\1.2.3.4\Share', response: connect_response) }
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
  let(:filename) { 'specfile.txt' }

  subject(:file) {
    described_class.new(tree: tree, response: nt_create_andx_response, name: filename)
  }

  it { is_expected.to respond_to :tree }
  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :attributes }
  it { is_expected.to respond_to :fid }
  it { is_expected.to respond_to :last_access }
  it { is_expected.to respond_to :last_change }
  it { is_expected.to respond_to :last_write }
  it { is_expected.to respond_to :size }
  it { is_expected.to respond_to :size_on_disk }

  it 'raises an exception when tree is no provided' do
    expect { described_class.new(tree: nil, response: nt_create_andx_response, name: filename) }.to raise_error(ArgumentError)
  end

  it 'raises an exception when response is no provided' do
    expect { described_class.new(tree: tree, response: nil, name: filename) }.to raise_error(ArgumentError)
  end

  it 'raises an exception when name is no provided' do
    expect { described_class.new(tree: tree, response: nt_create_andx_response, name: nil) }.to raise_error(ArgumentError)
  end

  it 'inherits the tree that spawned it' do
    expect(file.tree).to eq tree
  end

  it 'sets the file name to the name passed as argument' do
    expect(file.name).to eq filename
  end

  it 'inherits the attributes from the response packet' do
    expect(file.attributes).to eq nt_create_andx_response.parameter_block.ext_file_attributes
  end

  it 'inherits the file ID from the response packet' do
    expect(file.fid).to eq nt_create_andx_response.parameter_block.fid
  end

  it 'inherits the last_access from the response packet' do
    expect(file.last_access).to eq nt_create_andx_response.parameter_block.last_access_time.to_datetime
  end

  it 'inherits the last_change from the response packet' do
    expect(file.last_change).to eq nt_create_andx_response.parameter_block.last_change_time.to_datetime
  end

  it 'inherits the last_write from the response packet' do
    expect(file.last_write).to eq nt_create_andx_response.parameter_block.last_write_time.to_datetime
  end

  it 'inherits the size from the response packet' do
    expect(file.size).to eq nt_create_andx_response.parameter_block.end_of_file
  end

  it 'inherits the size_on_disk from the response packet' do
    expect(file.size_on_disk).to eq nt_create_andx_response.parameter_block.allocation_size
  end

  describe '#set_header_fields' do
    let(:request) { RubySMB::SMB1::Packet::ReadAndxRequest.new }
    it 'calls the set_header_field method from the Tree' do
      expect(tree).to receive(:set_header_fields).with(request).and_call_original
      file.set_header_fields(request)
    end

    it 'sets the packet file_id from the guid' do
      expect(file.set_header_fields(request).parameter_block.fid).to eq file.fid
    end
  end

  describe '#read_packet' do
    it 'creates a new ReadAndxRequest packet' do
      expect(RubySMB::SMB1::Packet::ReadAndxRequest).to receive(:new).and_call_original
      file.read_packet
    end

    it 'calls #set_header_fields to set ReadAndxRequest header fields' do
      request = RubySMB::SMB1::Packet::ReadAndxRequest.new
      allow(RubySMB::SMB1::Packet::ReadAndxRequest).to receive(:new).and_return(request)
      expect(file).to receive(:set_header_fields).with(request).and_call_original
      file.read_packet
    end

    it 'sets the read_length of the packet' do
      expect(file.read_packet(read_length: 55).parameter_block.max_count_of_bytes_to_return).to eq 55
    end

    it 'sets the offset of the packet' do
      expect(file.read_packet(offset: 55).parameter_block.offset).to eq 55
    end
  end

  describe '#read' do
    let(:read_data) { 'read data' }
    let(:raw_response) { double('fake raw response data') }
    let(:read_andx_response) {
      res = RubySMB::SMB1::Packet::ReadAndxResponse.new
      res.data_block.data = read_data
      res
    }

    before :example do
      allow(client).to receive(:send_recv).and_return(raw_response)
      allow(RubySMB::SMB1::Packet::ReadAndxResponse).to receive(:read).with(raw_response).and_return(read_andx_response)
    end

    context 'when the number of bytes to read is not provided' do
      it 'reads #size bytes by default' do
        expect(file).to receive(:read_packet).with(read_length: file.size, offset: 0).once.and_call_original
        expect(file.read).to eq(read_data)
      end
    end

    context 'when the number of bytes to read is less than or equal to max_buffer_size' do
      it 'reads only one packet with the number of bytes provided as argument' do
        client.max_buffer_size = read_data.size
        expect(file).to receive(:read_packet).with(read_length: read_data.size, offset: 0).once.and_call_original
        expect(file.read(bytes: read_data.size)).to eq(read_data)
      end
    end

    context 'when the number of bytes to read is greater than max_buffer_size' do
      it 'reads multiple packets with at most max_buffer_size bytes per chunk' do
        client.max_buffer_size = read_data.size - 1
        read_io = StringIO.new(read_data)
        expect(file).to receive(:read_packet).with(read_length: client.max_buffer_size, offset: 0).once.ordered.and_call_original
        expect(file).to receive(:read_packet).with(read_length: (read_data.size - client.max_buffer_size), offset: client.max_buffer_size).once.ordered.and_call_original
        allow(RubySMB::SMB1::Packet::ReadAndxResponse).to receive(:read).with(raw_response) do
          read_andx_response.data_block.data = read_io.read(client.max_buffer_size)
          read_andx_response
        end
        expect(file.read(bytes: read_data.size)).to eq(read_data)
      end
    end

    context 'when sending the request packet and gets a response back' do
      context 'when the response is not a ReadAndxResponse packet' do
        it 'raise an InvalidPacket exception' do
          read_andx_response.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_ECHO
          expect { file.read }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'when the response status code is not STATUS_SUCCESS' do
        it 'raise an UnexpectedStatusCode exception' do
          read_andx_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
          expect { file.read }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
        end
      end

      context 'when the response is an EmptyPacket with the SMB_COM_READ_ANDX command and STATUS_SUCCESS status code' do
        let(:empty_packet) do
          empty_packet = RubySMB::SMB1::Packet::EmptyPacket.new
          empty_packet.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_READ_ANDX
          empty_packet
        end

        it 'returns an empty string if it is the first request' do
          allow(RubySMB::SMB1::Packet::ReadAndxResponse).to receive(:read).with(raw_response).and_return(empty_packet)
          expect(file.read).to eq('')
        end

        it 'returns the current read data if it happens after the first request' do
          partial_data = read_data[0..-2]
          client.max_buffer_size = partial_data.size
          first_request = true
          allow(RubySMB::SMB1::Packet::ReadAndxResponse).to receive(:read).with(raw_response).twice do
            if first_request
              read_andx_response.data_block.data = partial_data
              first_request = false
              read_andx_response
            else
              empty_packet
            end
          end
          expect(file.read(bytes: read_data.size)).to eq(partial_data)
        end
      end
    end
  end

  describe '#write_packet' do
    it 'creates a new WriteAndxRequest packet' do
      expect(RubySMB::SMB1::Packet::WriteAndxRequest).to receive(:new).and_call_original
      file.write_packet
    end

    it 'calls #set_header_fields to set WriteAndxRequest headers' do
      request = RubySMB::SMB1::Packet::WriteAndxRequest.new
      allow(RubySMB::SMB1::Packet::WriteAndxRequest).to receive(:new).and_return(request)
      expect(file).to receive(:set_header_fields).with(request).and_call_original
      file.write_packet
    end

    it 'sets the offset of the packet' do
      expect(file.write_packet(offset: 55).parameter_block.offset).to eq 55
    end

    it 'sets the write_mode to writethrough_mode' do
      expect(file.write_packet.parameter_block.write_mode.writethrough_mode).to eq 1
    end

    it 'sets the remaining number of bytes to data_length value' do
      data = 'write data'
      write_andx_request = file.write_packet(data: data)
      expect(write_andx_request.parameter_block.remaining).to eq write_andx_request.parameter_block.data_length
      expect(write_andx_request.parameter_block.remaining).to eq data.size
    end

    it 'sets the data of the packet' do
      data = 'write data'
      expect(file.write_packet(data: data).data_block.data).to eq data
    end
  end

  describe '#write' do
    let(:write_data) { 'write data' }
    let(:raw_response) { double('fake raw response data') }
    let(:write_andx_response) do
      response = RubySMB::SMB1::Packet::WriteAndxResponse.new
      response.parameter_block.count_low = write_data.size
      response
    end

    before :example do
      allow(client).to receive(:send_recv).and_return(raw_response)
      allow(RubySMB::SMB1::Packet::WriteAndxResponse).to receive(:read).with(raw_response).and_return(write_andx_response)
    end

    describe 'offset' do
      it 'writes from offset 0 by default' do
        expect(file).to receive(:write_packet).with(data: write_data, offset: 0).and_call_original
        file.write(data: write_data)
      end

      it 'writes from the offset passed as arguement' do
        offset = 10
        expect(file).to receive(:write_packet).with(data: write_data, offset: offset).and_call_original
        file.write(data: write_data, offset: offset)
      end
    end

    context 'when the buffer size is less than or equal to max_buffer_size' do
      it 'sends only one packet with the entire buffer' do
        client.max_buffer_size = write_data.size
        expect(file).to receive(:write_packet).with(data: write_data, offset: 0).once.and_call_original
        expect(file.write(data: write_data)).to eq write_data.size
      end
    end

    context 'when the buffer size is greater than max_buffer_size' do
      it 'sends multiple packets with at most max_buffer_size bytes per chunk' do
        client.max_buffer_size = write_data.size - 1
        first_data_chunk = write_data[0, client.max_buffer_size]
        second_data_chunk = write_data[client.max_buffer_size..-1]
        original_write_packet = file.method(:write_packet)

        expect(file).to receive(:write_packet).with(data: first_data_chunk , offset: 0).once do
          allow(RubySMB::SMB1::Packet::WriteAndxResponse).to receive(:read).with(raw_response) do
            write_andx_response.parameter_block.count_low = first_data_chunk.size
            write_andx_response
          end
          original_write_packet.call(data: first_data_chunk, offset: 0)
        end
        expect(file).to receive(:write_packet).with(data: second_data_chunk, offset: client.max_buffer_size).once do
          allow(RubySMB::SMB1::Packet::WriteAndxResponse).to receive(:read).with(raw_response) do
            write_andx_response.parameter_block.count_low = second_data_chunk.size
            write_andx_response
          end
          original_write_packet.call(data: second_data_chunk, offset: client.max_buffer_size)
        end
        expect(file.write(data: write_data)).to eq write_data.size
      end
    end

    context 'when sending the request packet and gets a response back' do
      context 'when the response is not a WriteAndxResponse packet' do
        it 'raise an InvalidPacket exception' do
          write_andx_response.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_ECHO
          expect { file.write(data: write_data) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'when the response status code is not STATUS_SUCCESS' do
        it 'raise an UnexpectedStatusCode exception' do
          write_andx_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
          expect { file.write(data: write_data) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
        end
      end
    end
  end

  describe '#append' do
    it 'calls #write with the expected data and the offset set to the end of the file (file size)' do
      data = 'append data'
      expect(file).to receive(:write).with(data: data, offset: file.size)
      file.append(data: data)
    end
  end

  describe '#delete' do
    let(:set_info_res) { RubySMB::SMB1::Packet::Trans2::SetFileInformationResponse.new }

    before :example do
      allow(client).to receive(:send_recv)
      allow(RubySMB::SMB1::Packet::Trans2::SetFileInformationResponse).to receive(:read).and_return(set_info_res)
    end

    it 'calls #delete_packet' do
      expect(file).to receive(:delete_packet)
      file.delete
    end

    it 'returns the response NTStatus code' do
      status = WindowsError::NTStatus::STATUS_SUCCESS
      set_info_res.smb_header.nt_status = status.value
      expect(file.delete).to eq status
    end
  end

  describe '#delete_packet' do
    let(:request) do
      request = RubySMB::SMB1::Packet::Trans2::SetFileInformationRequest.new
      passthrough_info_level = RubySMB::Fscc::FileInformation::FILE_DISPOSITION_INFORMATION +
        RubySMB::Fscc::FileInformation::SMB_INFO_PASSTHROUGH
      request.data_block.trans2_parameters.information_level = passthrough_info_level
      request
    end

    before :example do
      allow(RubySMB::SMB1::Packet::Trans2::SetFileInformationRequest).to receive(:new).and_return(request)
    end

    it 'creates a new Trans2 SetFileInformationRequest packet' do
      expect(RubySMB::SMB1::Packet::Trans2::SetFileInformationRequest).to receive(:new).and_return(request)
      file.delete_packet
    end

    it 'calls Tree #set_header_fields to set SetFileInformationRequest headers' do
      expect(tree).to receive(:set_header_fields).with(request).and_call_original
      file.delete_packet
    end

    it 'sets the Trans2 parameter #fid of the packet with the File FID' do
      fid = 0x1000
      file.fid = fid
      expect(file.delete_packet.data_block.trans2_parameters.fid).to eq fid
    end

    it 'sets the Trans2 parameter #information_level of the packet' do
      request.data_block.trans2_parameters.information_level = 0
      passthrough_info_level = RubySMB::Fscc::FileInformation::FILE_DISPOSITION_INFORMATION +
        RubySMB::Fscc::FileInformation::SMB_INFO_PASSTHROUGH
      expect(file.delete_packet.data_block.trans2_parameters.information_level).to eq passthrough_info_level
    end

    it 'sets the File Information #delete_pending field of the packet' do
      expect(file.delete_packet.data_block.trans2_data.info_level_struct.delete_pending).to eq 1
    end

    it 'sets the Trans2 ParameterBlock fields' do
      parameter_block = file.delete_packet.parameter_block
      expect(parameter_block.total_parameter_count).to eq request.parameter_block.parameter_count
      expect(parameter_block.total_data_count).to eq request.parameter_block.data_count
      expect(parameter_block.max_parameter_count).to eq request.parameter_block.parameter_count
      expect(parameter_block.max_data_count).to eq 16_384
    end
  end

  describe '#rename' do
    let(:set_info_res) { RubySMB::SMB1::Packet::Trans2::SetFileInformationResponse.new }
    let(:filename) { 'file.txt' }

    before :example do
      allow(client).to receive(:send_recv)
      allow(RubySMB::SMB1::Packet::Trans2::SetFileInformationResponse).to receive(:read).and_return(set_info_res)
    end

    it 'calls #rename_packet' do
      expect(file).to receive(:rename_packet)
      file.rename(filename)
    end

    it 'returns the response NTStatus code' do
      status = WindowsError::NTStatus::STATUS_SUCCESS
      set_info_res.smb_header.nt_status = status.value
      expect(file.rename(filename)).to eq status
    end
  end

  describe '#rename_packet' do
    let(:request) do
      request = RubySMB::SMB1::Packet::Trans2::SetFileInformationRequest.new
      passthrough_info_level = RubySMB::Fscc::FileInformation::FILE_RENAME_INFORMATION +
        RubySMB::Fscc::FileInformation::SMB_INFO_PASSTHROUGH
      request.data_block.trans2_parameters.information_level = passthrough_info_level
      request
    end

    before :example do
      allow(RubySMB::SMB1::Packet::Trans2::SetFileInformationRequest).to receive(:new).and_return(request)
    end

    it 'creates a new Trans2 SetFileInformationRequest packet' do
      expect(RubySMB::SMB1::Packet::Trans2::SetFileInformationRequest).to receive(:new).and_return(request)
      file.rename_packet(filename)
    end

    it 'calls Tree #set_header_fields to set SetFileInformationRequest headers' do
      expect(tree).to receive(:set_header_fields).with(request).and_call_original
      file.rename_packet(filename)
    end

    it 'sets the Trans2 parameter #fid of the packet with the File FID' do
      fid = 0x1000
      file.fid = fid
      expect(file.rename_packet(filename).data_block.trans2_parameters.fid).to eq fid
    end

    it 'sets the Trans2 parameter #information_level of the packet' do
      request.data_block.trans2_parameters.information_level = 0
      passthrough_info_level = RubySMB::Fscc::FileInformation::FILE_RENAME_INFORMATION +
        RubySMB::Fscc::FileInformation::SMB_INFO_PASSTHROUGH
      expect(file.rename_packet(filename).data_block.trans2_parameters.information_level).to eq passthrough_info_level
    end

    it 'sets the File Information #rename_pending field of the packet' do
      expect(file.rename_packet(filename).data_block.trans2_data.info_level_struct.file_name).to eq filename.encode('utf-16le').force_encoding('ASCII-8BIT')
    end

    it 'sets the Trans2 ParameterBlock fields' do
      parameter_block = file.rename_packet(filename).parameter_block
      expect(parameter_block.total_parameter_count).to eq request.parameter_block.parameter_count
      expect(parameter_block.total_data_count).to eq request.parameter_block.data_count
      expect(parameter_block.max_parameter_count).to eq request.parameter_block.parameter_count
      expect(parameter_block.max_data_count).to eq 16_384
    end
  end

  context 'with DCERPC' do
    describe '#net_share_enum_all' do
      let(:host) { '1.2.3.4' }
      let(:dcerpc_response) { RubySMB::Dcerpc::Response.new }

      before :example do
        allow(file).to receive(:bind)
        allow(file).to receive(:request).and_return(dcerpc_response)
        allow(RubySMB::Dcerpc::Srvsvc::NetShareEnumAll).to receive(:parse_response).and_return([])
      end

      it 'calls #bind with the expected arguments' do
        expect(file).to receive(:bind).with(endpoint: RubySMB::Dcerpc::Srvsvc)
        file.net_share_enum_all(host)
      end

      it 'calls #request with the expected arguments' do
        expect(file).to receive(:request).with(RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL, host: host)
        file.net_share_enum_all(host)
      end

      it 'parse the response with NetShareEnumAll #parse_response method' do
        stub = 'ABCD'
        dcerpc_response.alloc_hint = stub.size
        dcerpc_response.stub = stub
        expect(RubySMB::Dcerpc::Srvsvc::NetShareEnumAll).to receive(:parse_response).with(stub)
        file.net_share_enum_all(host)
      end

      it 'returns the remote shares' do
        shares = [
          ["C$", "DISK", "Default share"],
          ["Shared", "DISK", ""],
          ["IPC$", "IPC", "Remote IPC"],
          ["ADMIN$", "DISK", "Remote Admin"]
        ]
        output = [
          {:name=>"C$", :type=>"DISK", :comment=>"Default share"},
          {:name=>"Shared", :type=>"DISK", :comment=>""},
          {:name=>"IPC$", :type=>"IPC", :comment=>"Remote IPC"},
          {:name=>"ADMIN$", :type=>"DISK", :comment=>"Remote Admin"},
        ]
        allow(RubySMB::Dcerpc::Srvsvc::NetShareEnumAll).to receive(:parse_response).and_return(shares)
        expect(file.net_share_enum_all(host)).to eq(output)
      end
    end

    describe '#bind' do
      let(:options) { { endpoint: RubySMB::Dcerpc::Srvsvc } }
      let(:bind_packet) { RubySMB::Dcerpc::Bind.new(options) }
      let(:bind_ack_packet) { RubySMB::Dcerpc::BindAck.new }

      before :example do
        allow(RubySMB::Dcerpc::Bind).to receive(:new).and_return(bind_packet)
        allow(file).to receive(:write)
        allow(file).to receive(:read)
        bind_ack_packet.p_result_list.n_results = 1
        bind_ack_packet.p_result_list.p_results[0].result = RubySMB::Dcerpc::BindAck::ACCEPTANCE
        allow(RubySMB::Dcerpc::BindAck).to receive(:read).and_return(bind_ack_packet)
      end

      it 'creates a Bind packet' do
        expect(RubySMB::Dcerpc::Bind).to receive(:new).with(options).and_return(bind_packet)
        file.bind(options)
      end

      it 'writes to the named pipe' do
        expect(file).to receive(:write).with(data: bind_packet.to_binary_s)
        file.bind(options)
      end

      it 'reads the socket' do
        expect(file).to receive(:read)
        file.bind(options)
      end

      it 'creates a BindAck packet from the response' do
        raw_response = RubySMB::Dcerpc::BindAck.new.to_binary_s
        allow(file).to receive(:read).and_return(raw_response)
        expect(RubySMB::Dcerpc::BindAck).to receive(:read).with(raw_response).and_return(bind_ack_packet)
        file.bind(options)
      end

      it 'raises the expected exception when an invalid packet is received' do
        allow(RubySMB::Dcerpc::BindAck).to receive(:read).and_raise(IOError)
        expect { file.bind(options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end

      it 'raises the expected exception when it is not a BindAck packet' do
        response = RubySMB::Dcerpc::Bind.new
        allow(RubySMB::Dcerpc::BindAck).to receive(:read).and_return(response)
        expect { file.bind(options) }.to raise_error(RubySMB::Dcerpc::Error::BindError)
      end

      it 'raises an exception when no result is returned' do
        bind_ack_packet.p_result_list.n_results = 0
        expect { file.bind(options) }.to raise_error(RubySMB::Dcerpc::Error::BindError)
      end

      it 'raises an exception when result is not ACCEPTANCE' do
        bind_ack_packet.p_result_list.p_results[0].result = RubySMB::Dcerpc::BindAck::USER_REJECTION
        expect { file.bind(options) }.to raise_error(RubySMB::Dcerpc::Error::BindError)
      end

      it 'returns the expected BindAck packet' do
        expect(file.bind(options)).to eq(bind_ack_packet)
      end
    end

    describe '#request' do
      let(:options) { { host: '1.2.3.4' } }
      let(:opnum) { RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL }
      let(:req_packet) { RubySMB::Dcerpc::Request.new({ :opnum => opnum }, options) }
      let(:nmpipe_packet) { RubySMB::SMB1::Packet::Trans::TransactNmpipeRequest.new(options) }
      let(:nmpipe_response) { RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse.new }
      let(:res_packet) { RubySMB::Dcerpc::Response.new }

      before :example do
        allow(RubySMB::Dcerpc::Request).to receive(:new).and_return(req_packet)
        allow(RubySMB::SMB1::Packet::Trans::TransactNmpipeRequest).to receive(:new).and_return(nmpipe_packet)
        allow(client).to receive(:send_recv)
        allow(RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse).to receive(:read).and_return(nmpipe_response)
        allow(RubySMB::Dcerpc::Response).to receive(:read).and_return(res_packet)
      end

      it 'creates a Request packet' do
        expect(RubySMB::Dcerpc::Request).to receive(:new).and_return(req_packet)
        file.request(opnum, options)
      end

      it 'creates a Trans TransactNmpipeRequest packet' do
        expect(RubySMB::SMB1::Packet::Trans::TransactNmpipeRequest).to receive(:new).and_return(nmpipe_packet)
        file.request(opnum, options)
      end

      it 'calls Tree #set_header_fields' do
        expect(tree).to receive(:set_header_fields).with(nmpipe_packet)
        file.request(opnum, options)
      end

      it 'calls TransactNmpipeRequest #set_fid' do
        expect(nmpipe_packet).to receive(:set_fid).with(file.fid)
        file.request(opnum, options)
      end

      it 'sets the expected data on the request' do
        expect(client).to receive(:send_recv) do
          expect(nmpipe_packet.data_block.trans_data.write_data).to eq(req_packet.to_binary_s)
        end
        file.request(opnum, options)
      end

      it 'sends the expected request' do
        expect(client).to receive(:send_recv).with(nmpipe_packet)
        file.request(opnum, options)
      end

      it 'creates a Trans TransactNmpipeResponse packet from the response' do
        raw_response = double('Raw response')
        allow(client).to receive(:send_recv).and_return(raw_response)
        expect(RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse).to receive(:read).with(raw_response).and_return(nmpipe_response)
        file.request(opnum, options)
      end

      it 'raises the expected exception when it is not a Trans packet' do
        response = RubySMB::SMB1::Packet::Trans2::Response.new
        allow(RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse).to receive(:read).and_return(response)
        expect { file.request(opnum, options) }.to raise_error(RubySMB::Error::InvalidPacket)
      end

      it 'raises the expected exception when the status code is not STATUS_SUCCESS' do
        nmpipe_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
        expect { file.request(opnum, options) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
      end

      it 'creates a DCERPC Response packet from the response' do
        nmpipe_response.data_block.trans_data.read_data = "test"
        expect(RubySMB::Dcerpc::Response).to receive(:read).with(nmpipe_response.data_block.trans_data.read_data)
        file.request(opnum, options)
      end

      it 'raises the expected exception when an invalid packet is received' do
        allow(RubySMB::Dcerpc::Response).to receive(:read).and_raise(IOError)
        expect { file.request(opnum, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end

      it 'raises the expected exception when it is not a Response packet' do
        response = RubySMB::Dcerpc::Request.new
        allow(RubySMB::Dcerpc::Response).to receive(:read).and_return(response)
        expect { file.request(opnum, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end

      it 'returns the expected DCERPC Response' do
        expect(file.request(opnum, options)).to eq(res_packet)
      end
    end
  end
end

