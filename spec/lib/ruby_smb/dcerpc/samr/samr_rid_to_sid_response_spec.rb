RSpec.describe RubySMB::Dcerpc::Samr::SamrRidToSidResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :sid }
  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#sid' do
    it 'is a PrpcSid structure' do
      expect(packet.sid).to be_a RubySMB::Dcerpc::Samr::PrpcSid
    end
  end
  describe '#error_status' do
    it 'is a NdrUint32 structure' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_RID_TO_SID constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_RID_TO_SID)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      sid: 'S-1-5-21-419547006-9459028-4093171872-500',
      error_status: 2
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
      sid: 'S-1-5-21-419547006-9459028-4093171872-500',
        error_status: 2
      }
    )
  end
end

