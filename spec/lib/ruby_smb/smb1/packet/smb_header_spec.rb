require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::SMBHeader do

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

  describe 'protocol' do
    it 'should be a 32-bit field per the SMB spec' do
      expect(header.protocol.num_bytes).to eq 4
    end

    it 'should be hardcoded to SMB_PROTOCOL_ID by default per the SMB spec' do
      expect(header.protocol).to eq RubySMB::SMB1::SMB_PROTOCOL_ID
    end
  end

  describe 'command' do
    it 'should be a 8-bit field per the SMB spec' do
      expect(header.command.num_bytes).to eq 1
    end
  end

  describe 'nt_status' do
    it 'should be a 32-bit field per the SMB spec' do
      expect(header.nt_status.num_bytes).to eq 4
    end
  end

  describe 'flags' do
    it 'should be a 8-bit field per the SMB spec' do
      expect(header.flags.num_bytes).to eq 1
    end
  end

  describe 'flags2' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.flags2.num_bytes).to eq 2
    end
  end

  describe 'pid_high' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.pid_high.num_bytes).to eq 2
    end
  end

  describe 'security_features' do
    it 'should be a 64-bit field per the SMB spec' do
      expect(header.security_features.num_bytes).to eq 8
    end
  end

  describe 'reserved' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.reserved.num_bytes).to eq 2
    end
  end

  describe 'tid' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.tid.num_bytes).to eq 2
    end
  end

  describe 'pid_low' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.pid_low.num_bytes).to eq 2
    end
  end

  describe 'uid' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.uid.num_bytes).to eq 2
    end
  end

  describe 'mid' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.mid.num_bytes).to eq 2
    end
  end
end