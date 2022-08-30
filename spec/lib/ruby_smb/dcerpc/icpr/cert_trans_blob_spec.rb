RSpec.describe RubySMB::Dcerpc::Icpr::CertTransBlob do
  subject(:struct) { described_class.new }

  it { is_expected.to respond_to :cb }
  it { is_expected.to respond_to :pb }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(struct).to be_a(BinData::Record)
  end
  describe '#cb' do
    it 'is a NdrUint32 structure' do
      expect(struct.cb).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#pb' do
    it 'is a NdrByteConfArrayPtr structure' do
      expect(struct.pb).to be_a RubySMB::Dcerpc::Ndr::NdrByteConfArrayPtr
    end
  end
  describe '#buffer' do
    it 'returns a string' do
      expect(struct.buffer).to be_a String
    end
  end
  it 'reads itself' do
    new_struct = described_class.new({ pb: 'BUFFER' })
    expected_output = { cb: 6, pb: 'BUFFER'.bytes }
    expect(struct.read(new_struct.to_binary_s)).to eq(expected_output)
  end
end
