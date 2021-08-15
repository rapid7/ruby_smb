RSpec.describe RubySMB::Gss::Provider::NTLM::OSVersion do
  subject(:os_version) { RubySMB::Gss::Provider::NTLM::OSVersion.new }

  it { is_expected.to respond_to :major }
  it { is_expected.to respond_to :minor }
  it { is_expected.to respond_to :build }
  it { is_expected.to respond_to :ntlm_revision }

  describe '#initialize' do
    it 'defaults to an NTLM revision of 15' do
      expect(os_version.ntlm_revision).to eq 15
    end
  end

  describe '#read' do
    it 'reads a packed version correctly' do
      # Version 6.1 (Build 7601); NTLM Current Revision 15
      os_version = RubySMB::Gss::Provider::NTLM::OSVersion.read("\x06\x01\x1d\xb1\x00\x00\x00\x0f")
      expect(os_version.major).to eq 6
      expect(os_version.minor).to eq 1
      expect(os_version.build).to eq 7601
      expect(os_version.ntlm_revision).to eq 15
    end
  end

  describe '#to_s' do
    it 'creates a string representation of the OS version' do
      expect(os_version.to_s).to be_a String
      expect(os_version.to_s).to match /Version \d+\.\d+ \(Build \d+\); NTLM Current Revision \d+/
    end
  end
end
