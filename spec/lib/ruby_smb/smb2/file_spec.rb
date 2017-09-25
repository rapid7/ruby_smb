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
      expect(file.delete_packet.file_info_class).to eq 13
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
      expect(file.rename_packet('new_file.txt').file_info_class).to eq 0x0A
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
        expect(file.rename('new_file.txt')[:smb2_header][:command]).to eq 17
      end
    end
  end
end
