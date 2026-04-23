require 'spec_helper'

RSpec.describe RubySMB::Rap::NetShareEnum do
  let(:client) { instance_double(RubySMB::Client) }
  let(:tree) { instance_double(RubySMB::SMB1::Tree, id: 1, client: client) }
  let(:pipe) do
    captured_tree = tree
    p = RubySMB::SMB1::Pipe.allocate
    p.instance_variable_set(:@tree, captured_tree)
    p.define_singleton_method(:tree) { captured_tree }
    p.extend(described_class)
    p
  end

  def build_rap_response(status:, entries: [])
    resp = RubySMB::SMB1::Packet::Trans::Response.new
    params = RubySMB::Rap::NetShareEnum::Response.new(
      status: status, converter: 0, entry_count: entries.length, available: entries.length
    )
    data = entries.map do |e|
      si = RubySMB::Rap::NetShareEnum::ShareInfo1.new(
        netname: e[:name], pad1: 0, share_type: e[:type], remark_offset: 0
      )
      si.to_binary_s
    end.join
    resp.data_block.trans_parameters = params.to_binary_s
    resp.data_block.trans_data = data
    resp.to_binary_s
  end

  describe '.new request layout' do
    it 'encodes the RAP NetShareEnum opcode, descriptors, level and buffer size' do
      bytes = RubySMB::Rap::NetShareEnum::Request.new.to_binary_s
      expect(bytes[0, 2]).to eq([0].pack('v'))         # opcode
      expect(bytes[2, 6]).to eq("WrLeh\x00")            # param descriptor
      expect(bytes[8, 7]).to eq("B13BWz\x00")           # data descriptor
      expect(bytes[15, 2]).to eq([1].pack('v'))         # info level 1
      expect(bytes[17, 2]).to eq([0x1000].pack('v'))    # receive buffer size
    end
  end

  describe '#net_share_enum' do
    it 'returns the parsed share list on RAP status 0' do
      entries = [
        { name: 'IPC$', type: 0x0003 }, # STYPE_IPC
        { name: 'DATA', type: 0x0000 }  # STYPE_DISKTREE
      ]
      allow(client).to receive(:send_recv).and_return(build_rap_response(status: 0, entries: entries))
      expect(pipe.net_share_enum).to eq([
        { name: 'IPC$', type: 0x0003 },
        { name: 'DATA', type: 0x0000 }
      ])
    end

    it 'sends a Trans request targeting \\PIPE\\LANMAN with the tree id' do
      allow(client).to receive(:send_recv) do |request|
        expect(request).to be_a(RubySMB::SMB1::Packet::Trans::Request)
        expect(request.smb_header.tid).to eq(tree.id)
        expect(request.smb_header.flags2.unicode).to eq(0)
        expect(request.data_block.name.to_s).to eq("\\PIPE\\LANMAN".b)
        expect(request.data_block.trans_parameters.to_s).to eq(RubySMB::Rap::NetShareEnum::Request.new.to_binary_s)
        build_rap_response(status: 0)
      end
      pipe.net_share_enum
    end

    it 'raises RubySMBError when the RAP status is non-zero' do
      allow(client).to receive(:send_recv).and_return(build_rap_response(status: 5))
      expect {
        pipe.net_share_enum
      }.to raise_error(RubySMB::Error::RubySMBError, /RAP NetShareEnum failed with status 0x5/)
    end

    it 'raises InvalidPacket when the RAP params are truncated' do
      resp = RubySMB::SMB1::Packet::Trans::Response.new
      resp.data_block.trans_parameters = "\x00\x00\x00"
      resp.data_block.trans_data = ''
      allow(client).to receive(:send_recv).and_return(resp.to_binary_s)
      expect {
        pipe.net_share_enum
      }.to raise_error(RubySMB::Error::InvalidPacket)
    end

    it 'raises UnexpectedStatusCode when the SMB status is not success' do
      resp = RubySMB::SMB1::Packet::Trans::Response.new
      resp.smb_header.nt_status = WindowsError::NTStatus::STATUS_ACCESS_DENIED.value
      resp.data_block.trans_parameters = RubySMB::Rap::NetShareEnum::Response.new(
        status: 0, converter: 0, entry_count: 0, available: 0
      ).to_binary_s
      resp.data_block.trans_data = ''
      allow(client).to receive(:send_recv).and_return(resp.to_binary_s)
      expect {
        pipe.net_share_enum
      }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
    end
  end

  describe 'SMB1::Pipe integration' do
    it 'extends the pipe with NetShareEnum when opened as \\PIPE\\LANMAN' do
      # Use a minimal response to drive Pipe#initialize through File#initialize.
      nt_resp = RubySMB::SMB1::Packet::NtCreateAndxResponse.new
      nt_resp.parameter_block.fid = 0x1001
      nt_resp.parameter_block.resource_type = RubySMB::SMB1::ResourceType::BYTE_MODE_PIPE
      p = RubySMB::SMB1::Pipe.new(tree: tree, response: nt_resp, name: '\\PIPE\\LANMAN')
      expect(p).to respond_to(:net_share_enum)
    end
  end
end
