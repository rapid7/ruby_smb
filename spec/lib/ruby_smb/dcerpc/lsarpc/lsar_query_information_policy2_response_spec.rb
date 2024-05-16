require 'ruby_smb/dcerpc/ndr'
require 'ruby_smb/dcerpc/lsarpc'

RSpec.describe RubySMB::Dcerpc::Lsarpc::LsarQueryInformationPolicy2Response do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :policy_information }
  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#policy_information' do
    it 'is an LsaprPolicyInformationPtr structure' do
      expect(packet.policy_information).to be_a RubySMB::Dcerpc::Lsarpc::LsaprPolicyInformationPtr
    end
  end
  describe '#error_status' do
    it 'is an NdrUint32 structure' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to LSAR_QUERY_INFORMATION_POLICY2 constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Lsarpc::LSAR_QUERY_INFORMATION_POLICY2)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      policy_information: {
        policy_information_class: 1,
        policy_information: {}
      }
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      policy_information: {
        policy_information_class: 1,
        policy_information: {
          audit_log_percent_full: 0,
          maximum_log_size: 0,
          audit_retention_period: 0,
          audit_log_full_shutdown_in_progress: 0,
          time_to_shutdown: 0,
          next_audit_record_id: 0
        }
      },
      error_status: 0
    )
  end
end
