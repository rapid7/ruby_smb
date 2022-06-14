RSpec.describe RubySMB::Dcerpc::Samr::SamrSetInformationUser2Response do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end

  describe '#error_status' do
    it 'is a NdrUint32 structure' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_SET_INFORMATION_USER2 constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_SET_INFORMATION_USER2)
    end
  end

  it 'reads itself' do
    new_class = described_class.new(error_status: 0x11223344)
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        error_status: 0x11223344
      }
    )
  end
end
