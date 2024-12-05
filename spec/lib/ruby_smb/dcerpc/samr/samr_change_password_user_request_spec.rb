RSpec.describe RubySMB::Dcerpc::Samr::SamrChangePasswordUserRequest do
  subject(:packet) { described_class.new }

  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_CHANGE_PASSWORD_USER constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_CHANGE_PASSWORD_USER)
    end
  end

  it 'reads itself' do
    uuid = RubySMB::Dcerpc::Uuid.new
    uuid.set(SecureRandom.uuid)
    new_packet = described_class.new({
      user_handle: RubySMB::Dcerpc::Samr::SamprHandle.new(context_handle_attributes: 42, :context_handle_uuid => uuid),
      lm_present: 1,
      old_lm_encrypted_with_new_lm: RubySMB::Dcerpc::Samr::PencryptedNtOwfPassword.new(buffer: SecureRandom::bytes(16)),
      new_lm_encrypted_with_old_lm: RubySMB::Dcerpc::Samr::PencryptedNtOwfPassword.new(buffer: SecureRandom::bytes(16)),
      nt_present: 1,
      old_nt_encrypted_with_new_nt: RubySMB::Dcerpc::Samr::PencryptedNtOwfPassword.new(buffer: SecureRandom::bytes(16)),
      new_nt_encrypted_with_old_nt: RubySMB::Dcerpc::Samr::PencryptedNtOwfPassword.new(buffer: SecureRandom::bytes(16)),
      nt_cross_encryption_present: 1,
      new_nt_encrypted_with_new_nt: RubySMB::Dcerpc::Samr::PencryptedNtOwfPassword.new(buffer: SecureRandom::bytes(16)),
      lm_cross_encryption_present: 1,
      new_lm_encrypted_with_new_nt: RubySMB::Dcerpc::Samr::PencryptedNtOwfPassword.new(buffer: SecureRandom::bytes(16))
    })
    expect(packet.read(new_packet.to_binary_s)).to eq(new_packet)
  end
end
