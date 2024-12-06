RSpec.describe RubySMB::Dcerpc::Samr::SamrUnicodeChangePasswordUser2Request do
  subject(:packet) { described_class.new }

  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_UNICODE_CHANGE_PASSWORD_USER2 constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_UNICODE_CHANGE_PASSWORD_USER2)
    end
  end

  it 'reads itself' do
    new_packet = described_class.new({
      server_name: 'my-server',
      user_name: 'user.person',
      new_password_encrypted_with_old_nt: RubySMB::Dcerpc::Samr::PsamprEncryptedUserPassword.new(buffer: SecureRandom::bytes(516)),
      pencrypted_nt_owf_password: RubySMB::Dcerpc::Samr::PencryptedNtOwfPassword.new(buffer: SecureRandom::bytes(16)),
      lm_present: 1,
      new_password_encrypted_with_old_lm: RubySMB::Dcerpc::Samr::PsamprEncryptedUserPassword.new(buffer: SecureRandom::bytes(516)),
      old_lm_owf_password_encrypted_with_new_nt: RubySMB::Dcerpc::Samr::PencryptedNtOwfPassword.new(buffer: SecureRandom::bytes(16)),
    })
    expect(packet.read(new_packet.to_binary_s)).to eq(new_packet)
  end
end
