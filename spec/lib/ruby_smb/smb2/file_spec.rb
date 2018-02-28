require 'spec_helper'
require 'securerandom'

RSpec.describe RubySMB::SMB2::File do
  let(:sock) { double('Socket', peeraddr: '192.168.1.5') }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(sock) }

  let(:client) { RubySMB::Client.new(dispatcher, username: 'msfadmin', password: 'msfadmin') }
  let(:tree_id) { 2049 }
  let(:path) { '\\192.168.1.1\example' }
  let(:connect_response) {
    packet = RubySMB::SMB2::Packet::TreeConnectResponse.new
    packet.smb2_header.tree_id = tree_id
    packet.maximal_access.read("\xff\x01\x1f\x00")
    packet.share_type = 0x01
    packet
  }

  let(:disco_req) { RubySMB::SMB2::Packet::TreeDisconnectRequest.new }
  let(:disco_resp) { RubySMB::SMB2::Packet::TreeDisconnectResponse.new }
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

  subject(:file) { described_class.new(name: 'short.txt', response: create_response, tree: tree) }

  it { is_expected.to respond_to :attributes }
  it { is_expected.to respond_to :guid }
  it { is_expected.to respond_to :last_access }
  it { is_expected.to respond_to :last_change }
  it { is_expected.to respond_to :last_write }
  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :size }
  it { is_expected.to respond_to :size_on_disk }
  it { is_expected.to respond_to :tree }

  it 'pulls the attributes from the response packet' do
    expect(file.attributes).to eq create_response.file_attributes
  end

  it 'pulls the GUID from the response fileid' do
    expect(file.guid).to eq create_response.file_id
  end

  it 'pulls the timestamps from the response packet' do
    expect(file.last_access).to eq create_response.last_access.to_datetime
  end

  it 'pulls the size from the response packet' do
    expect(file.size).to eq create_response.end_of_file
  end

  it 'pulls the size_on_disk from the response packet' do
    expect(file.size_on_disk).to eq create_response.allocation_size
  end

  describe '#set_header_fields' do
    let(:request) { RubySMB::SMB2::Packet::ReadRequest.new }
    it 'calls the set_header_field method from the Tree' do
      expect(tree).to receive(:set_header_fields).with(request).and_call_original
      file.set_header_fields(request)
    end

    it 'sets the packet file_id from the guid' do
      expect(file.set_header_fields(request).file_id).to eq file.guid
    end
  end

  describe '#read_packet' do
    it 'creates a new ReadRequest packet' do
      expect(RubySMB::SMB2::Packet::ReadRequest).to receive(:new).and_call_original
      file.read_packet
    end

    it 'calls #set_header_fields' do
      expect(file).to receive(:set_header_fields).and_call_original
      file.read_packet
    end

    it 'sets the read_length of the packet' do
      expect(file.read_packet(read_length: 55).read_length).to eq 55
    end

    it 'sets the offset of the packet' do
      expect(file.read_packet(offset: 55).offset).to eq 55
    end
  end

  describe '#read' do
    context 'for a small file' do
      let(:small_read) { file.read_packet(read_length: 108) }
      let(:small_response) { RubySMB::SMB2::Packet::ReadResponse.new(data_length: 9, buffer: 'fake data') }

      it 'uses a single packet to read the entire file' do
        expect(file).to receive(:read_packet).with(read_length: 108, offset: 0).and_return(small_read)
        expect(client).to receive(:send_recv).with(small_read).and_return 'fake data'
        expect(RubySMB::SMB2::Packet::ReadResponse).to receive(:read).with('fake data').and_return(small_response)
        expect(file.read).to eq 'fake data'
      end
    end

    context 'for a larger file' do
      let(:big_read) { file.read_packet(read_length: 108) }
      let(:big_response) { RubySMB::SMB2::Packet::ReadResponse.new(data_length: 9, buffer: 'fake data') }

      it 'uses a multiple packet to read the file in chunks' do
        expect(file).to receive(:read_packet).once.with(read_length: described_class::MAX_PACKET_SIZE, offset: 0).and_return(big_read)
        expect(file).to receive(:read_packet).once.with(read_length: described_class::MAX_PACKET_SIZE, offset: described_class::MAX_PACKET_SIZE).and_return(big_read)
        expect(client).to receive(:send_recv).twice.and_return 'fake data'
        expect(RubySMB::SMB2::Packet::ReadResponse).to receive(:read).twice.with('fake data').and_return(big_response)
        file.read(bytes: (described_class::MAX_PACKET_SIZE * 2))
      end
    end
  end

  describe '#append' do
    it 'call #write with offset set to the end of the file' do
      expect(file).to receive(:write).with(data:'test', offset: file.size)
      file.append(data:'test')
    end
  end

  describe '#write_packet' do
    it 'calls #set_header_fields with the newly created packet' do
      expect(file).to receive(:set_header_fields).and_call_original
      file.write_packet
    end

    it 'sets the offset on the packet' do
      expect(file.write_packet(offset:5).write_offset).to eq 5
    end

    it 'sets the buffer on the packet' do
      expect(file.write_packet(data:'hello').buffer).to eq 'hello'
    end
  end

  describe '#write' do
    let(:write_response) { RubySMB::SMB2::Packet::WriteResponse.new }
    context 'for a small write' do
      it 'sends a single packet' do
        expect(client).to receive(:send_recv).once.and_return(write_response.to_binary_s)
        file.write(data: 'test')
      end
    end

    context 'for a large write' do
      it 'sends multiple packets' do
        expect(client).to receive(:send_recv).twice.and_return(write_response.to_binary_s)
        file.write(data: SecureRandom.random_bytes(described_class::MAX_PACKET_SIZE + 1))
      end
    end
  end

  describe '#delete_packet' do
    it 'creates a new SetInfoRequest packet' do
      expect(RubySMB::SMB2::Packet::SetInfoRequest).to receive(:new).and_call_original
      file.delete_packet
    end

    it 'calls #set_header_fields' do
      expect(file).to receive(:set_header_fields).and_call_original
      file.delete_packet
    end

    it 'sets the file_info_class of the packet' do
      expect(file.delete_packet.file_info_class).to eq RubySMB::Fscc::FileInformation::FILE_DISPOSITION_INFORMATION
    end

    it 'sets the delete_pending field to 1' do
      expect(file.delete_packet.buffer.delete_pending).to eq 1
    end
  end

  describe '#delete' do
    context 'for a small file' do
      let(:small_delete) { file.delete_packet }
      let(:small_response) { RubySMB::SMB2::Packet::SetInfoResponse.new }

      it 'uses a single packet to delete the entire file' do
        expect(file).to receive(:delete_packet).and_return(small_delete)
        expect(client).to receive(:send_recv).with(small_delete).and_return 'raw_response'
        expect(RubySMB::SMB2::Packet::SetInfoResponse).to receive(:read).with('raw_response').and_return(small_response)
        expect(file.delete).to eq WindowsError::NTStatus::STATUS_SUCCESS
      end
    end
  end

  describe '#rename_packet' do
    it 'creates a new SetInfoRequest packet' do
      expect(RubySMB::SMB2::Packet::SetInfoRequest).to receive(:new).and_call_original
      file.rename_packet('new_file.txt')
    end

    it 'calls #set_header_fields' do
      expect(file).to receive(:set_header_fields).and_call_original
      file.rename_packet('new_file.txt')
    end

    it 'sets the file_info_class of the packet' do
      expect(file.rename_packet('new_file.txt').file_info_class).to eq RubySMB::Fscc::FileInformation::FILE_RENAME_INFORMATION
    end

    it 'sets the file_name field to the unicode-encoded new file name' do
      filename = "new_file.txt"
      expect(file.rename_packet(filename).buffer.file_name).to eq filename.encode('UTF-16LE').force_encoding('ASCII-8BIT')
    end
  end

  describe '#rename' do
    context 'for a small file' do
      let(:small_rename) { file.rename_packet('new_file.txt') }
      let(:small_response) { RubySMB::SMB2::Packet::SetInfoResponse.new }

      it 'uses a single packet to rename the entire file' do
        expect(file).to receive(:rename_packet).and_return(small_rename)
        expect(client).to receive(:send_recv).with(small_rename).and_return 'raw_response'
        expect(RubySMB::SMB2::Packet::SetInfoResponse).to receive(:read).with('raw_response').and_return(small_response)
        expect(file.rename('new_file.txt')).to eq WindowsError::NTStatus::STATUS_SUCCESS
      end
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
      let(:ioctl_response) { RubySMB::SMB2::Packet::IoctlResponse.new }
      let(:bind_ack_packet) { RubySMB::Dcerpc::BindAck.new }

      before :example do
        allow(RubySMB::Dcerpc::Bind).to receive(:new).and_return(bind_packet)
        allow(file).to receive(:ioctl_send_recv).and_return(ioctl_response)
        bind_ack_packet.p_result_list.n_results = 1
        bind_ack_packet.p_result_list.p_results[0].result = RubySMB::Dcerpc::BindAck::ACCEPTANCE
        bind_ack_packet.p_result_list.p_results[0].transfer_syntax.read(RubySMB::Dcerpc::NdrSyntax.new.to_binary_s)
        allow(RubySMB::Dcerpc::BindAck).to receive(:read).and_return(bind_ack_packet)
      end

      it 'creates a Bind packet' do
        expect(RubySMB::Dcerpc::Bind).to receive(:new).with(options).and_return(bind_packet)
        file.bind(options)
      end

      it 'calls #ioctl_send_recv' do
        expect(file).to receive(:ioctl_send_recv).with(bind_packet, options)
        file.bind(options)
      end

      it 'creates a BindAck packet from the response' do
        expect(RubySMB::Dcerpc::BindAck).to receive(:read).with(ioctl_response.output_data).and_return(bind_ack_packet)
        file.bind(options)
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
      let(:ioctl_response) { RubySMB::SMB2::Packet::IoctlResponse.new }
      let(:res_packet) { RubySMB::Dcerpc::Response.new }

      before :example do
        allow(RubySMB::Dcerpc::Request).to receive(:new).and_return(req_packet)
        allow(file).to receive(:ioctl_send_recv).and_return(ioctl_response)
        allow(RubySMB::Dcerpc::Response).to receive(:read).and_return(res_packet)
      end

      it 'creates a Request packet' do
        expect(RubySMB::Dcerpc::Request).to receive(:new).and_return(req_packet)
        file.request(opnum, options)
      end

      it 'calls #ioctl_send_recv' do
        expect(file).to receive(:ioctl_send_recv).with(req_packet, options)
        file.request(opnum, options)
      end

      it 'creates a DCERPC Response packet from the response' do
        expect(RubySMB::Dcerpc::Response).to receive(:read).with(ioctl_response.output_data)
        file.request(opnum, options)
      end

      it 'returns the expected DCERPC Response' do
        expect(file.request(opnum, options)).to eq(res_packet)
      end
    end

    describe '#ioctl_send_recv' do
      let(:action) { RubySMB::Dcerpc::Request.new({ :opnum => RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL }, host: '1.2.3.4') }
      let(:options) { {} }
      let(:ioctl_request) { RubySMB::SMB2::Packet::IoctlRequest.new(options) }
      let(:ioctl_response) { RubySMB::SMB2::Packet::IoctlResponse.new }

      before :example do
        allow(client).to receive(:send_recv).and_return(ioctl_response.to_binary_s)
      end

      it 'calls File #set_header_fields' do
        expect(file).to receive(:set_header_fields).with(ioctl_request).and_call_original
        file.ioctl_send_recv(action, options)
      end

      it 'calls Client #send_recv with the expected request' do
        expect(client).to receive(:send_recv) do |req|
          expect(req.ctl_code).to eq(0x0011C017)
          expect(req.flags.is_fsctl).to eq(0x00000001)
          expect(req.buffer).to eq(action.to_binary_s)
          ioctl_response.to_binary_s
        end
        file.ioctl_send_recv(action, options)
      end

      it 'creates a IoctlResponse packet from the response' do
        expect(RubySMB::SMB2::Packet::IoctlResponse).to receive(:read).with(ioctl_response.to_binary_s)
        file.ioctl_send_recv(action, options)
      end

      it 'returns the expected DCERPC Response' do
        expect(file.ioctl_send_recv(action, options)).to eq(ioctl_response)
      end
    end

  end
end
