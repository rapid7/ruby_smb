require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::TreeConnectRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :flags }
  it { is_expected.to respond_to :path_offset }
  it { is_expected.to respond_to :path_length }
  it { is_expected.to respond_to :path }
  it { is_expected.to respond_to :tree_connect_request_extension }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#smb2_header' do
    subject(:header) { packet.smb2_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB2::SMB2Header
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB2::Commands::TREE_CONNECT
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  describe '#structure_size' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.structure_size).to be_a BinData::Uint16le
    end

    it 'should have a default value of 9 as per the SMB2 spec' do
      expect(packet.structure_size).to eq 9
    end
  end

  describe '#flags' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.flags).to be_a BinData::Uint16le
    end
  end

  describe '#path_offset' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.path_offset).to be_a BinData::Uint16le
    end

    context 'when flags is set to SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT' do
      it 'should be set to the offset, in bytes, of the full share path name from the beginning of the packet header' do
        packet.flags = described_class::SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT
        expect(packet.path_offset).to eq(88)
      end
    end

    context 'when flags is not set to SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT' do
      it 'should be set to the offset, in bytes, of the full share path name from the beginning of the packet header' do
        expect(packet.path_offset).to eq(72)
      end
    end
  end

  describe '#path_length' do
    let(:path) { '\\\\server\\path' }

    it 'should be a 16-bit unsigned integer' do
      expect(packet.path_length).to be_a BinData::Uint16le
    end

    context 'when flags is set to SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT' do
      it 'should be the length of the full share path name (unicode) in bytes' do
        packet.flags = described_class::SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT
        packet.tree_connect_request_extension.path = path
        expect(packet.path_length).to eq(path.length * 2)
      end
    end

    context 'when flags is not set to SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT' do
      it 'should be the length of the full share path name (unicode) in bytes' do
        packet.path = path
        expect(packet.path_length).to eq(path.length * 2)
      end
    end
  end

  describe '#path' do
    it 'should be a unicode string' do
      expect(packet.path).to be_a RubySMB::Field::String16
    end

    it 'exists if #flags is not set to SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT' do
      packet.flags = described_class::SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER
      expect(packet.path?).to be true
    end
  end

  describe '#tree_connect_request_extension' do
    it 'is a TreeConnectRequestExtension structure' do
      expect(packet.tree_connect_request_extension).to be_a RubySMB::SMB2::Packet::TreeConnectRequestExtension
    end

    it 'exists if #flags is set to SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT' do
      packet.flags = described_class::SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT
      expect(packet.tree_connect_request_extension?).to be true
    end
  end

  it 'reads a binary data as expected' do
    data = described_class.new
    expect(described_class.read(data.to_binary_s)).to eq(data)
    data = described_class.new(flags: described_class::SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT)
    data.tree_connect_request_extension.tree_connect_contexts << RubySMB::SMB2::Packet::TreeConnectContext.new(context_type: 1)
    expect(described_class.read(data.to_binary_s)).to eq(data)
  end
end

RSpec.describe RubySMB::SMB2::Packet::TreeConnectRequestExtension do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :tree_connect_context_offset }
  it { is_expected.to respond_to :tree_connect_context_count }
  it { is_expected.to respond_to :reserved }
  it { is_expected.to respond_to :path }
  it { is_expected.to respond_to :tree_connect_contexts }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#tree_connect_context_offset' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.tree_connect_context_offset).to be_a BinData::Uint32le
    end

    it 'is the offset from the start of the SMB2 TREE_CONNECT request of an array of tree connect contexts' do
      tc = RubySMB::SMB2::Packet::TreeConnectRequest.new(
        flags: RubySMB::SMB2::Packet::TreeConnectRequest::SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT
      )
      expect(tc.tree_connect_request_extension.tree_connect_context_offset).to eq(16)
    end
  end

  describe '#tree_connect_context_count' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.tree_connect_context_count).to be_a BinData::Uint16le
    end

    it 'should be the #tree_connect_contexts size' do
      packet.tree_connect_contexts << RubySMB::SMB2::Packet::TreeConnectContext.new(context_type: 1)
      packet.tree_connect_contexts << RubySMB::SMB2::Packet::TreeConnectContext.new(context_type: 1)
      expect(packet.tree_connect_context_count).to eq(2)
    end
  end

  describe '#reserved' do
    it 'should be a binary string' do
      expect(packet.reserved).to be_a BinData::String
    end

    it 'is is 10-bytes long' do
      expect(packet.reserved.length).to eq(10)
    end
  end

  describe '#path' do
    it 'should be a unicode string' do
      expect(packet.path).to be_a RubySMB::Field::String16
    end
  end

  describe '#tree_connect_contexts' do
    it 'is an Array field' do
      expect(packet.tree_connect_contexts).to be_a BinData::Array
    end

    it 'has #tree_connect_context_count elements' do
      packet.tree_connect_context_count = 3
      expect(packet.tree_connect_contexts.size).to eq(3)
    end
  end

  it 'reads a binary data as expected' do
    data = described_class.new
    expect(described_class.read(data.to_binary_s)).to eq(data)
    data.tree_connect_contexts << RubySMB::SMB2::Packet::TreeConnectContext.new(context_type: 1)
    data.tree_connect_contexts << RubySMB::SMB2::Packet::TreeConnectContext.new(context_type: 1)
    expect(described_class.read(data.to_binary_s)).to eq(data)
  end
end

RSpec.describe RubySMB::SMB2::Packet::TreeConnectContext do
  subject(:packet) do
    described_class.new(
      context_type: described_class::SMB2_REMOTED_IDENTITY_TREE_CONNECT_CONTEXT_ID
    )
  end

  it { is_expected.to respond_to :context_type }
  it { is_expected.to respond_to :data_length }
  it { is_expected.to respond_to :reserved }
  it { is_expected.to respond_to :data }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#context_type' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.context_type).to be_a BinData::Uint16le
    end
  end

  describe '#data_length' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.data_length).to be_a BinData::Uint16le
    end

    it 'is the length, in bytes, of the Data field' do
      expect(packet.data_length).to eq(packet.data.to_binary_s.size)
    end
  end

  describe '#reserved' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.reserved).to be_a BinData::Uint32le
    end
  end

  describe '#data' do
    it 'is a BinData Choice' do
      expect(packet.data).to be_a BinData::Choice
    end

    it 'contains the structure defined by #context_type' do
      expect(packet.data).to eq(RubySMB::SMB2::Packet::RemotedIdentityTreeConnectContext.new)
    end
  end

  it 'reads a binary data as expected' do
    data = described_class.new(context_type: 1)
    expect(described_class.read(data.to_binary_s)).to eq(data)
  end
end

RSpec.describe RubySMB::SMB2::Packet::RemotedIdentityTreeConnectContext do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :ticket_type }
  it { is_expected.to respond_to :ticket_size }
  it { is_expected.to respond_to :user }
  it { is_expected.to respond_to :user_name }
  it { is_expected.to respond_to :domain }
  it { is_expected.to respond_to :groups }
  it { is_expected.to respond_to :restricted_groups }
  it { is_expected.to respond_to :privileges }
  it { is_expected.to respond_to :primary_group }
  it { is_expected.to respond_to :owner }
  it { is_expected.to respond_to :default_dacl }
  it { is_expected.to respond_to :device_groups }
  it { is_expected.to respond_to :user_claims }
  it { is_expected.to respond_to :device_claims }
  it { is_expected.to respond_to :ticket_info }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#ticket_type' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.ticket_type).to be_a BinData::Uint16le
    end

    it 'should be 1' do
      expect(packet.ticket_type).to eq(1)
    end
  end

  describe '#ticket_size' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.ticket_size).to be_a BinData::Uint16le
    end

    it 'is the total size of this structure' do
      packet.ticket_info = 'Ticket Info'
      expect(packet.ticket_size).to eq(packet.num_bytes)
    end
  end

  describe '#user' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.user).to be_a BinData::Uint16le
    end
  end

  describe '#user_name' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.user_name).to be_a BinData::Uint16le
    end
  end

  describe '#domain' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.domain).to be_a BinData::Uint16le
    end
  end

  describe '#groups' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.groups).to be_a BinData::Uint16le
    end
  end

  describe '#restricted_groups' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.restricted_groups).to be_a BinData::Uint16le
    end
  end

  describe '#privileges' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.privileges).to be_a BinData::Uint16le
    end
  end

  describe '#primary_group' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.primary_group).to be_a BinData::Uint16le
    end
  end

  describe '#owner' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.owner).to be_a BinData::Uint16le
    end
  end

  describe '#default_dacl' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.default_dacl).to be_a BinData::Uint16le
    end
  end

  describe '#device_groups' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.device_groups).to be_a BinData::Uint16le
    end
  end

  describe '#user_claims' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.user_claims).to be_a BinData::Uint16le
    end
  end

  describe '#device_claims' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.device_claims).to be_a BinData::Uint16le
    end
  end

  describe '#ticket_info' do
    it 'should be string' do
      expect(packet.ticket_info).to be_a BinData::String
    end
  end

  it 'reads a binary data as expected' do
    data = described_class.new(ticket_info: 'ticket info')
    expect(described_class.read(data.to_binary_s)).to eq(data)
  end
end
