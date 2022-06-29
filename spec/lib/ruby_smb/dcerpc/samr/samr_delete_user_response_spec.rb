RSpec.describe RubySMB::Dcerpc::Samr::SamrDeleteUserResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :user_handle }
  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end

  describe '#user_handle' do
    it 'is a SamprHandle structure' do
      expect(packet.user_handle).to be_a RubySMB::Dcerpc::Samr::SamprHandle
    end
  end

  describe '#error_status' do
    it 'is a NdrUint32 structure' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_DELETE_USER constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_DELETE_USER)
    end
  end

  it 'reads itself' do
    new_packet = described_class.new({
      user_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: "fc873b90-d9a9-46a4-b9ea-f44bb1c272a7"
      },
      error_status: 0x11223344
    })
    expected_output = {
      user_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: "fc873b90-d9a9-46a4-b9ea-f44bb1c272a7"
      },
      error_status: 0x11223344
    }
    expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
  end
end
