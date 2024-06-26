RSpec.describe RubySMB::Dcerpc::Lsarpc::LsarCloseHandleRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :policy_handle }
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
  describe '#initialize_instance' do
    it 'sets #opnum to LSAR_CLOSE_HANDLE constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Lsarpc::LSAR_CLOSE_HANDLE)
    end
  end
  it 'reads itself' do
    new_packet = described_class.new(
      policy_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: "fc873b90-d9a9-46a4-b9ea-f44bb1c272a7"
      }
    )
    expected_output = {
      policy_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: "fc873b90-d9a9-46a4-b9ea-f44bb1c272a7"
      }
    }
    expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
  end
end


