RSpec.describe RubySMB::Dcerpc::Samr::SamrCreateUser2InDomainRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :domain_handle }
  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :account_type }
  it { is_expected.to respond_to :desired_access }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end

  describe '#domain_handle' do
    it 'is a SamprHandle structure' do
      expect(packet.domain_handle).to be_a RubySMB::Dcerpc::Samr::SamprHandle
    end
  end

  describe '#name' do
    it 'is a RpcUnicodeString' do
      expect(packet.name).to be_a RubySMB::Dcerpc::RpcUnicodeString
    end
  end

  describe '#account_type' do
    it 'is a NdrUint32 structure' do
      expect(packet.account_type).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#desired_access' do
    it 'is a NdrUint32 structure' do
      expect(packet.desired_access).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_CREATE_USER2_IN_DOMAIN constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_CREATE_USER2_IN_DOMAIN)
    end
  end

  it 'reads itself' do
    new_packet = described_class.new({
      domain_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: "fc873b90-d9a9-46a4-b9ea-f44bb1c272a7"
      },
      name: 'test',
      account_type: 1,
      desired_access: 2
    })
    expected_output = {
      domain_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: "fc873b90-d9a9-46a4-b9ea-f44bb1c272a7"
      },
      name: {:buffer=>"test".encode('utf-16le'), :buffer_length=>8, :maximum_length=>8},
      account_type: 1,
      desired_access: 2
    }
    expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
  end
end
