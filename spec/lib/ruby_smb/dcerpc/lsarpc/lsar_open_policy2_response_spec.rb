
RSpec.describe RubySMB::Dcerpc::Lsarpc::LsarOpenPolicy2Response do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :policy_handle }
  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#policy_handle' do
    it 'is an LsaprHandle structure' do
      expect(packet.policy_handle).to be_a RubySMB::Dcerpc::Lsarpc::LsaprHandle
    end
  end
  describe '#error_status' do
    it 'is a NdrUint32' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to LSAR_OPEN_POLICY2 constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Lsarpc::LSAR_OPEN_POLICY2)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      policy_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: "fc873b90-d9a9-46a4-b9ea-f44bb1c272a7"
      },
      error_status: 0
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      policy_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: "fc873b90-d9a9-46a4-b9ea-f44bb1c272a7"
      },
      error_status: 0
    )
  end
end
