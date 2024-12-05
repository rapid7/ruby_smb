RSpec.describe RubySMB::Dcerpc::Samr::SamrUnicodeChangePasswordUser2Response do
  subject(:packet) { described_class.new }

  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_UNICODE_CHANGE_PASSWORD_USER2 constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_UNICODE_CHANGE_PASSWORD_USER2)
    end
  end

  it 'reads itself' do
    new_packet = described_class.new({
      error_status: 4
    })
    expect(packet.read(new_packet.to_binary_s)).to eq(new_packet)
  end
end
