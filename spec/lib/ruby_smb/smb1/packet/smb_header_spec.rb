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
      protocol_size_field = header.fields.detect { |f| f.name == :protocol }
      expect(protocol_size_field.length).to eq 32
    end

    it 'should be hardcoded to SMB_PROTOCOL_ID by default per the SMB spec' do
      expect(header.protocol).to eq RubySMB::SMB1::SMB_PROTOCOL_ID
    end
  end

  describe 'command' do
    it 'should be a 8-bit field per the SMB spec' do
      command_size_field = header.fields.detect { |f| f.name == :command }
      expect(command_size_field.length).to eq 8
    end
  end

  describe 'nt_status' do
    it 'should be a 32-bit field per the SMB spec' do
      nt_status_size_field = header.fields.detect { |f| f.name == :nt_status }
      expect(nt_status_size_field.length).to eq 32
    end
  end

  describe 'flags' do
    it 'should be a 8-bit field per the SMB spec' do
      flags_size_field = header.fields.detect { |f| f.name == :flags }
      expect(flags_size_field.length).to eq 8
    end
  end

  describe 'flags2' do
    it 'should be a 16-bit field per the SMB spec' do
      flags2_size_field = header.fields.detect { |f| f.name == :flags2 }
      expect(flags2_size_field.length).to eq 16
    end
  end

  describe 'pid_high' do
    it 'should be a 16-bit field per the SMB spec' do
      pid_high_size_field = header.fields.detect { |f| f.name == :pid_high }
      expect(pid_high_size_field.length).to eq 16
    end
  end

  describe 'security_features' do
    it 'should be a 64-bit field per the SMB spec' do
      security_features_size_field = header.fields.detect { |f| f.name == :security_features }
      expect(security_features_size_field.length).to eq 64
    end
  end

  describe 'reserved' do
    it 'should be a 16-bit field per the SMB spec' do
      reserved_size_field = header.fields.detect { |f| f.name == :reserved }
      expect(reserved_size_field.length).to eq 16
    end
  end

  describe 'tid' do
    it 'should be a 16-bit field per the SMB spec' do
      tid_size_field = header.fields.detect { |f| f.name == :tid }
      expect(tid_size_field.length).to eq 16
    end
  end

  describe 'pid_low' do
    it 'should be a 16-bit field per the SMB spec' do
      pid_low_size_field = header.fields.detect { |f| f.name == :pid_low }
      expect(pid_low_size_field.length).to eq 16
    end
  end

  describe 'uid' do
    it 'should be a 16-bit field per the SMB spec' do
      uid_size_field = header.fields.detect { |f| f.name == :uid }
      expect(uid_size_field.length).to eq 16
    end
  end

  describe 'mid' do
    it 'should be a 16-bit field per the SMB spec' do
      mid_size_field = header.fields.detect { |f| f.name == :mid }
      expect(mid_size_field.length).to eq 16
    end
  end
end