RSpec.describe RubySMB::Dcerpc::Lsarpc::LsarCloseHandleResponse do
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
    it 'is a LsaprHandle structure' do
      expect(packet.policy_handle).to be_a RubySMB::Dcerpc::Lsarpc::LsaprHandle
    end
  end
  describe '#error_status' do
    it 'is a NdrUint32 structure' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to LSAR_CLOSE_HANDLE constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Lsarpc::LSAR_CLOSE_HANDLE)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      policy_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: '2ef54a87-e29e-4d24-90e9-9da49b94449e'
      },
      error_status: 0
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        policy_handle: {
          context_handle_attributes: 0,
          context_handle_uuid: '2ef54a87-e29e-4d24-90e9-9da49b94449e'
        },
        error_status: 0
      })
  end
end
