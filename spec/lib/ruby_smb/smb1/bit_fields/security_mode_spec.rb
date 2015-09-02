RSpec.describe RubySMB::SMB1::BitFields::SecurityMode do
  subject(:security_mode) { described_class.new }

  it { is_expected.to respond_to :user_security }
  it { is_expected.to respond_to :encrypt_passwords }
  it { is_expected.to respond_to :security_signatures_enabled }
  it { is_expected.to respond_to :security_signatures_required }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@endian)).to eq :little
  end

  describe '#user_security' do
    it 'is a 1-bit flag' do
      expect(security_mode.user_security).to be_a BinData::Bit1
    end
  end

  describe '#encrypt_passwords' do
    it 'is a 1-bit flag' do
      expect(security_mode.encrypt_passwords).to be_a BinData::Bit1
    end
  end

  describe '#security_signatures_enabled' do
    it 'is a 1-bit flag' do
      expect(security_mode.security_signatures_enabled).to be_a BinData::Bit1
    end
  end

  describe '#security_signatures_required' do
    it 'is a 1-bit flag' do
      expect(security_mode.security_signatures_required).to be_a BinData::Bit1
    end
  end

end
