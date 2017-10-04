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
      allow(client).to receive(:parse_response).with(response_packet: RubySMB::SMB1::Packet::ReadAndxResponse, raw_response: raw_response).and_return(read_andx_response)
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
        allow(client).to receive(:parse_response).with(response_packet: RubySMB::SMB1::Packet::ReadAndxResponse, raw_response: raw_response) do
          read_andx_response.data_block.data = read_io.read(client.max_buffer_size)
          read_andx_response
        end
        expect(file.read(bytes: read_data.size)).to eq(read_data)
      end
    end

    context 'when the response is an EmptyPacket with the SMB_COM_READ_ANDX command and STATUS_SUCCESS status code' do
      it 'returns an empty string if it is the first request' do
        allow(client).to receive(:parse_response).with(response_packet: RubySMB::SMB1::Packet::ReadAndxResponse, raw_response: raw_response).and_return(RubySMB::SMB1::Packet::EmptyPacket.new)
        expect(file.read).to eq('')
      end

      it 'returns the current read data if it happens after the first request' do
        partial_data = read_data[0..-2]
        client.max_buffer_size = partial_data.size
        first_request = true
        allow(client).to receive(:parse_response).with(response_packet: RubySMB::SMB1::Packet::ReadAndxResponse, raw_response: raw_response).twice do
          if first_request
            read_andx_response.data_block.data = partial_data
            first_request = false
            read_andx_response
          else
            RubySMB::SMB1::Packet::EmptyPacket.new
          end
        end
        expect(file.read(bytes: read_data.size)).to eq(partial_data)
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
    let(:write_andx_response) { RubySMB::SMB1::Packet::WriteAndxResponse.new }

    before :example do
      allow(client).to receive(:send_recv).and_return(raw_response)
      allow(client).to receive(:parse_response).with(response_packet: RubySMB::SMB1::Packet::WriteAndxResponse, raw_response: raw_response).and_return(write_andx_response)
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
        expect(file.write(data: write_data)).to eq WindowsError::NTStatus::STATUS_SUCCESS
      end
    end

    context 'when the buffer size is greater than max_buffer_size' do
      it 'sends multiple packets with at most max_buffer_size bytes per chunk' do
        client.max_buffer_size = write_data.size - 1
        buffer = write_data.dup
        expect(file).to receive(:write_packet).with(data: buffer.slice!(0, client.max_buffer_size), offset: 0).once.ordered.and_call_original
        expect(file).to receive(:write_packet).with(data: buffer, offset: client.max_buffer_size).once.ordered.and_call_original
        expect(file.write(data: write_data)).to eq WindowsError::NTStatus::STATUS_SUCCESS
      end
    end

    context 'when an error occured' do
      it 'returns the status' do
        write_andx_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_ACCESS_DENIED.value
        expect(file.write(data: write_data)).to eq WindowsError::NTStatus::STATUS_ACCESS_DENIED
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

end

