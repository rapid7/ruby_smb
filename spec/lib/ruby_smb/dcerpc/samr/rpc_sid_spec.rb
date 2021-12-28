RSpec.describe RubySMB::Dcerpc::Samr::RpcSidIdentifierAuthority do
  subject(:packet) { described_class.new }

  it 'is a Ndr::NdrFixArray' do
    expect(packet).to be_a(RubySMB::Dcerpc::Ndr::NdrFixArray)
  end
  it 'has element of type :ndr_uint8' do
    expect(packet[0]).to be_a(RubySMB::Dcerpc::Ndr::NdrUint8)
  end
  it 'has 6 elements by default' do
    expect(packet.size).to eq(6)
  end
  it 'is one-byte aligned' do
    expect(packet.eval_parameter(:byte_align)).to eq(1)
  end
  it 'reads itself' do
    expect(packet.read(described_class.new([1, 2, 3, 4, 5, 6]).to_binary_s)).to eq([1, 2, 3, 4, 5, 6])
  end
end

RSpec.describe RubySMB::Dcerpc::Samr::RpcSid do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :revision }
  it { is_expected.to respond_to :sub_authority_count }
  it { is_expected.to respond_to :identifier_authority }
  it { is_expected.to respond_to :sub_authority }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a Ndr::NdrStruct' do
    expect(packet).to be_a(RubySMB::Dcerpc::Ndr::NdrStruct)
  end
  it 'is four-byte aligned' do
    expect(packet.eval_parameter(:byte_align)).to eq(4)
  end
  describe '#revision' do
    it 'is a NdrUint8 structure' do
      expect(packet.revision).to be_a RubySMB::Dcerpc::Ndr::NdrUint8
    end
  end
  describe '#sub_authority_count' do
    it 'is a NdrUint8 structure' do
      expect(packet.sub_authority_count).to be_a RubySMB::Dcerpc::Ndr::NdrUint8
    end
    it 'is set the the number of #sub_authority elements by default' do
      packet.sub_authority = [21, 419547006, 9459028, 4093171872, 500]
      expect(packet.sub_authority_count).to eq(5)
    end
  end
  describe '#identifier_authority' do
    it 'is a RpcSidIdentifierAuthority structure' do
      expect(packet.identifier_authority).to be_a RubySMB::Dcerpc::Samr::RpcSidIdentifierAuthority
    end
  end
  describe '#sub_authority' do
    it 'is a NdrConfArray structure' do
      expect(packet.sub_authority).to be_a RubySMB::Dcerpc::Ndr::NdrConfArray
    end
    it 'has element of type :ndr_uint32' do
      packet.sub_authority << 1
      expect(packet.sub_authority[0]).to be_a(RubySMB::Dcerpc::Ndr::NdrUint32)
    end
  end
  describe '#snapshot' do
    it 'outputs the expected SID' do
      packet.revision = 1
      packet.identifier_authority = [0, 0, 0, 0, 0, 5]
      packet.sub_authority = [21, 419547006, 9459028, 4093171872, 500]
      expect(packet.snapshot).to eq('S-1-5-21-419547006-9459028-4093171872-500')
    end
  end
  describe '#assign' do
    it 'assign the correct fields from a String' do
      packet.assign('S-1-5-21-419547006-9459028-4093171872-500')
      expect(packet.revision).to eq(1)
      expect(packet.sub_authority_count).to eq(5)
      expect(packet.identifier_authority).to eq([0, 0, 0, 0, 0, 5])
      expect(packet.sub_authority).to eq([21, 419547006, 9459028, 4093171872, 500])
    end
    it 'assign the correct fields from another RpcSid object' do
      packet2 = described_class.new
      packet2.revision = 1
      packet2.identifier_authority = [0, 0, 0, 0, 0, 5]
      packet2.sub_authority = [21, 419547006, 9459028, 4093171872, 500]
      packet.assign(packet2)
      expect(packet.revision).to eq(1)
      expect(packet.sub_authority_count).to eq(5)
      expect(packet.identifier_authority).to eq([0, 0, 0, 0, 0, 5])
      expect(packet.sub_authority).to eq([21, 419547006, 9459028, 4093171872, 500])
      expect(packet.snapshot).to eq('S-1-5-21-419547006-9459028-4093171872-500')
    end
  end
  it 'reads itself' do
    expect(packet.read(described_class.new('S-1-5-21-419547006-9459028-4093171872-500').to_binary_s)).to eq('S-1-5-21-419547006-9459028-4093171872-500')
  end
end

RSpec.describe RubySMB::Dcerpc::Samr::PrpcSid do
  subject(:packet) { described_class.new }

  it 'is a RpcSid' do
    expect(packet).to be_a(RubySMB::Dcerpc::Samr::RpcSid)
  end
  it 'is a NdrPointer' do
    expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
    expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
  end
  it 'is four-byte aligned' do
    expect(packet.eval_parameter(:byte_align)).to eq(4)
  end
  it 'reads itself' do
    expect(packet.read(described_class.new('S-1-5-21-419547006-9459028-4093171872-500').to_binary_s)).to eq('S-1-5-21-419547006-9459028-4093171872-500')
  end
end
