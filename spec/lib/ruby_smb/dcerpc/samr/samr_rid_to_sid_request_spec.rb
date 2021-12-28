RSpec.describe RubySMB::Dcerpc::Samr::SamrRidToSidRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :object_handle }
  it { is_expected.to respond_to :rid }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#object_handle' do
    it 'is a SamprHandle structure' do
      expect(packet.object_handle).to be_a RubySMB::Dcerpc::Samr::SamprHandle
    end
  end
  describe '#rid' do
    it 'is a NdrUint32 structure' do
      expect(packet.rid).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_RID_TO_SID constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_RID_TO_SID)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      object_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: '2ef54a87-e29e-4d24-90e9-9da49b94449e'
      },
      rid: 502
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        object_handle: {
          context_handle_attributes: 0,
          context_handle_uuid: '2ef54a87-e29e-4d24-90e9-9da49b94449e'
        },
        rid: 502
      }
    )
  end
end

