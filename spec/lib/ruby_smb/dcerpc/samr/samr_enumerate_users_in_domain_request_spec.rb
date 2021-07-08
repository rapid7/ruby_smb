RSpec.describe RubySMB::Dcerpc::Samr::SamrEnumerateUsersInDomainRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :domain_handle }
  it { is_expected.to respond_to :enumeration_context }
  it { is_expected.to respond_to :user_account_control }
  it { is_expected.to respond_to :prefered_maximum_length }
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
  describe '#enumeration_context' do
    it 'is a NdrUint32 structure' do
      expect(packet.enumeration_context).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#user_account_control' do
    it 'is a NdrUint32 structure' do
      expect(packet.user_account_control).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#prefered_maximum_length' do
    it 'is a NdrUint32 structure' do
      expect(packet.prefered_maximum_length).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_ENUMERATE_USERS_IN_DOMAIN constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_ENUMERATE_USERS_IN_DOMAIN)
    end
  end
  it 'reads itself' do
    new_packet = described_class.new({
      domain_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: "fc873b90-d9a9-46a4-b9ea-f44bb1c272a7"
      },
      enumeration_context: 44,
      user_account_control: 123,
      prefered_maximum_length: 65535
    })
    expected_output = {
      domain_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: "fc873b90-d9a9-46a4-b9ea-f44bb1c272a7"
      },
      enumeration_context: 44,
      user_account_control: 123,
      prefered_maximum_length: 65535
    }
    expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
  end
end

