RSpec.describe RubySMB::Dcerpc::Samr::UserAccountControl do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :user_encrypted_text_password_allowed }
  it { is_expected.to respond_to :user_passwd_cant_change }
  it { is_expected.to respond_to :user_passwd_notreqd }
  it { is_expected.to respond_to :user_lockout }
  it { is_expected.to respond_to :user_homedir_required }
  it { is_expected.to respond_to :reserved1 }
  it { is_expected.to respond_to :user_account_disabled }
  it { is_expected.to respond_to :user_script }
  it { is_expected.to respond_to :reserved3 }
  it { is_expected.to respond_to :user_server_trust_account }
  it { is_expected.to respond_to :user_workstation_trust_account }
  it { is_expected.to respond_to :user_interdomain_trust_account }
  it { is_expected.to respond_to :reserved2 }
  it { is_expected.to respond_to :user_normal_account }
  it { is_expected.to respond_to :user_temp_duplicate_account }
  it { is_expected.to respond_to :user_password_expired }
  it { is_expected.to respond_to :user_dont_require_preauth }
  it { is_expected.to respond_to :user_use_des_key_only }
  it { is_expected.to respond_to :user_not_delegated }
  it { is_expected.to respond_to :user_trusted_for_delegation }
  it { is_expected.to respond_to :user_smartcard_required }
  it { is_expected.to respond_to :user_mns_logon_account }
  it { is_expected.to respond_to :user_dont_expire_passwd }
  it { is_expected.to respond_to :reserved4 }
  it { is_expected.to respond_to :user_no_auth_data_required }
  it { is_expected.to respond_to :user_trusted_to_authenticate_for_delegation }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a Ndr::NdrStruct' do
    expect(packet).to be_a(RubySMB::Dcerpc::Ndr::NdrStruct)
  end
  it 'is four-byte aligned' do
    expect(packet.eval_parameter(:byte_align)).to eq(4)
  end
  describe '#user_encrypted_text_password_allowed' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_encrypted_text_password_allowed).to be_a BinData::Bit1
    end
  end
  describe '#user_passwd_cant_change' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_passwd_cant_change).to be_a BinData::Bit1
    end
  end
  describe '#user_passwd_notreqd' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_passwd_notreqd).to be_a BinData::Bit1
    end
  end
  describe '#user_lockout' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_lockout).to be_a BinData::Bit1
    end
  end
  describe '#user_homedir_required' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_homedir_required).to be_a BinData::Bit1
    end
  end
  describe '#reserved1' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.reserved1).to be_a BinData::Bit1
    end
  end
  describe '#user_account_disabled' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_account_disabled).to be_a BinData::Bit1
    end
  end
  describe '#user_script' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_script).to be_a BinData::Bit1
    end
  end
  describe '#reserved3' do
    it 'is a BinData::Bit2 structure' do
      expect(packet.reserved3).to be_a BinData::Bit2
    end
  end
  describe '#user_server_trust_account' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_server_trust_account).to be_a BinData::Bit1
    end
  end
  describe '#user_workstation_trust_account' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_workstation_trust_account).to be_a BinData::Bit1
    end
  end
  describe '#user_interdomain_trust_account' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_interdomain_trust_account).to be_a BinData::Bit1
    end
  end
  describe '#reserved2' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.reserved2).to be_a BinData::Bit1
    end
  end
  describe '#user_normal_account' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_normal_account).to be_a BinData::Bit1
    end
  end
  describe '#user_temp_duplicate_account' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_temp_duplicate_account).to be_a BinData::Bit1
    end
  end
  describe '#user_password_expired' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_password_expired).to be_a BinData::Bit1
    end
  end
  describe '#user_dont_require_preauth' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_dont_require_preauth).to be_a BinData::Bit1
    end
  end
  describe '#user_use_des_key_only' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_use_des_key_only).to be_a BinData::Bit1
    end
  end
  describe '#user_not_delegated' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_not_delegated).to be_a BinData::Bit1
    end
  end
  describe '#user_trusted_for_delegation' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_trusted_for_delegation).to be_a BinData::Bit1
    end
  end
  describe '#user_smartcard_required' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_smartcard_required).to be_a BinData::Bit1
    end
  end
  describe '#user_mns_logon_account' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_mns_logon_account).to be_a BinData::Bit1
    end
  end
  describe '#user_dont_expire_passwd' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_dont_expire_passwd).to be_a BinData::Bit1
    end
  end
  describe '#reserved4' do
    it 'is a BinData::Bit6 structure' do
      expect(packet.reserved4).to be_a BinData::Bit6
    end
  end
  describe '#user_no_auth_data_required' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_no_auth_data_required).to be_a BinData::Bit1
    end
  end
  describe '#user_trusted_to_authenticate_for_delegation' do
    it 'is a BinData::Bit1 structure' do
      expect(packet.user_trusted_to_authenticate_for_delegation).to be_a BinData::Bit1
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      user_script: 1,
      user_server_trust_account: 1,
      user_mns_logon_account: 1,
      user_trusted_to_authenticate_for_delegation: 1
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        user_encrypted_text_password_allowed: 0,
        user_passwd_cant_change: 0,
        user_passwd_notreqd: 0,
        user_lockout: 0,
        user_homedir_required: 0,
        reserved1: 0,
        user_account_disabled: 0,
        user_script: 1,
        reserved3: 0,
        user_server_trust_account: 1,
        user_workstation_trust_account: 0,
        user_interdomain_trust_account: 0,
        reserved2: 0,
        user_normal_account: 0,
        user_temp_duplicate_account: 0,
        user_password_expired: 0,
        user_dont_require_preauth: 0,
        user_use_des_key_only: 0,
        user_not_delegated: 0,
        user_trusted_for_delegation: 0,
        user_smartcard_required: 0,
        user_mns_logon_account: 1,
        user_dont_expire_passwd: 0,
        reserved4: 0,
        user_no_auth_data_required: 0,
        user_trusted_to_authenticate_for_delegation: 1
      }
    )
  end
end

