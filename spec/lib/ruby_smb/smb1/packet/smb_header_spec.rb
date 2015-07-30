require 'spec_helper'

RSpec.describe RubySMB::Smb1::Packet::SmbHeader do

  subject(:header) { described_class.new }

  it { is_expected.to respond_to :protocol }
  it { is_expected.to respond_to :command }
  it { is_expected.to respond_to :nt_status }
  it { is_expected.to respond_to :flags }
  it { is_expected.to respond_to :flags2 }
  it { is_expected.to respond_to :pid_high }
  it { is_expected.to respond_to :security_features }
  it { is_expected.to respond_to :reserved }
  it { is_expected.to respond_to :tid }
  it { is_expected.to respond_to :pid_low }
  it { is_expected.to respond_to :uid }
  it { is_expected.to respond_to :mid }

  describe 'defaults' do
    it 'sets protocol to the SMB_PROTOCOL_ID by default' do
      expect(header.protocol).to eq RubySMB::Smb1::SMB_PROTOCOL_ID
    end
  end
end