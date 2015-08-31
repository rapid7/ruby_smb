RSpec.shared_examples 'smb header' do

  it { is_expected.to respond_to :protocol }
  it { is_expected.to respond_to :command }
  it { is_expected.to respond_to :nt_status }
  it { is_expected.to respond_to :flags_reply }
  it { is_expected.to respond_to :flags_opbatch }
  it { is_expected.to respond_to :flags_oplock }
  it { is_expected.to respond_to :flags_canonicalized_paths }
  it { is_expected.to respond_to :flags_case_insensitive }
  it { is_expected.to respond_to :flags_reserved }
  it { is_expected.to respond_to :flags_buf_avail }
  it { is_expected.to respond_to :flags_lock_and_read_ok }
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
      expect(header.protocol).to be_a BinData::Bit32
    end

    it 'should be hardcoded to SMB_PROTOCOL_ID by default per the SMB spec' do
      expect(header.protocol).to eq RubySMB::SMB1::SMB_PROTOCOL_ID
    end
  end

  describe 'command' do
    it 'should be a 8-bit field per the SMB spec' do
      expect(header.command).to be_a BinData::Bit8
    end
  end

  describe 'nt_status' do
    it 'should be a 32-bit field per the SMB spec' do
      expect(header.nt_status).to be_a BinData::Bit32
    end
  end

  describe 'flags_reply' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags_reply).to be_a BinData::Bit1
    end
  end

  describe 'flags_opbatch' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags_opbatch).to be_a BinData::Bit1
    end
  end

  describe 'flags_oplock' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags_oplock).to be_a BinData::Bit1
    end
  end

  describe 'flags_canonicalized_paths' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags_canonicalized_paths).to be_a BinData::Bit1
    end
  end

  describe 'flags_case_insensitive' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags_case_insensitive).to be_a BinData::Bit1
    end
  end

  describe 'flags_reserved' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags_reserved).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(header.flags_reserved).to eq 0
    end
  end

  describe 'flags_buf_avail' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags_buf_avail).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(header.flags_buf_avail).to eq 0
    end
  end

  describe 'flags_lock_and_read_ok' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags_lock_and_read_ok).to be_a BinData::Bit1
    end
  end

  describe 'flags2' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.flags2).to be_a BinData::Bit16
    end
  end

  describe 'pid_high' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.pid_high).to be_a BinData::Bit16
    end
  end

  describe 'security_features' do
    it 'should be a 64-bit field per the SMB spec' do
      expect(header.security_features).to be_a BinData::Bit64
    end
  end

  describe 'reserved' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.reserved).to be_a BinData::Bit16
    end
  end

  describe 'tid' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.tid).to be_a BinData::Bit16
    end
  end

  describe 'pid_low' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.pid_low).to be_a BinData::Bit16
    end
  end

  describe 'uid' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.uid).to be_a BinData::Bit16
    end
  end

  describe 'mid' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.mid).to be_a BinData::Bit16
    end
  end
end