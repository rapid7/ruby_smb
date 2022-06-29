RSpec.describe RubySMB::Dcerpc::Samr::SamrSetInformationUser2Request do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :user_handle }
  it { is_expected.to respond_to :user_information_class }
  it { is_expected.to respond_to :buffer }
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

  describe '#user_information_class' do
    it 'is a NdrUint16 structure' do
      expect(packet.user_information_class).to be_a RubySMB::Dcerpc::Ndr::NdrUint16
    end
  end

  describe '#buffer' do
    it 'is a SamprUserInfoBuffer structure' do
      expect(packet.buffer).to be_a RubySMB::Dcerpc::Samr::SamprUserInfoBuffer
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_SET_INFORMATION_USER2 constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_SET_INFORMATION_USER2)
    end
  end

  it 'reads itself' do
    new_class = described_class.new(
      user_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: '2ef54a87-e29e-4d24-90e9-9da49b94449e'
      },
      user_information_class: RubySMB::Dcerpc::Samr::USER_CONTROL_INFORMATION,
      buffer: {
        tag: RubySMB::Dcerpc::Samr::USER_CONTROL_INFORMATION,
        member: { user_account_control: RubySMB::Dcerpc::Samr::USER_WORKSTATION_TRUST_ACCOUNT }
      }
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        user_handle: {
          context_handle_attributes: 0,
          context_handle_uuid: '2ef54a87-e29e-4d24-90e9-9da49b94449e'
        },
        user_information_class: RubySMB::Dcerpc::Samr::USER_CONTROL_INFORMATION,
        buffer: {
          tag: RubySMB::Dcerpc::Samr::USER_CONTROL_INFORMATION,
          member: { user_account_control: RubySMB::Dcerpc::Samr::USER_WORKSTATION_TRUST_ACCOUNT }
        }
      }
    )
  end
end
