RSpec.describe RubySMB::SMB1::Packet::SMBHeader do

  subject(:header) { described_class.new }

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
  it { is_expected.to respond_to :flags2_unicode }
  it { is_expected.to respond_to :flags2_nt_status }
  it { is_expected.to respond_to :flags2_paging_io }
  it { is_expected.to respond_to :flags2_dfs }
  it { is_expected.to respond_to :flags2_extended_security }
  it { is_expected.to respond_to :flags2_reparse_path }
  it { is_expected.to respond_to :flags2_reserved1 }
  it { is_expected.to respond_to :flags2_is_long_name }
  it { is_expected.to respond_to :flags2_reserved2 }
  it { is_expected.to respond_to :flags2_signature_required }
  it { is_expected.to respond_to :flags2_compressed }
  it { is_expected.to respond_to :flags2_security_signature }
  it { is_expected.to respond_to :flags2_eas }
  it { is_expected.to respond_to :flags2_long_names }
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

    it 'should have a default value of 0' do
      expect(header.flags_opbatch).to eq 0
    end
  end

  describe 'flags_oplock' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags_oplock).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(header.flags_oplock).to eq 0
    end
  end

  describe 'flags_canonicalized_paths' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags_canonicalized_paths).to be_a BinData::Bit1
    end

    it 'should have a default value of 1' do
      expect(header.flags_canonicalized_paths).to eq 1
    end
  end

  describe 'flags_case_insensitive' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags_case_insensitive).to be_a BinData::Bit1
    end

    it 'should have a default value of 1' do
      expect(header.flags_case_insensitive).to eq 1
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

  describe 'flags2_unicode' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags2_unicode).to be_a BinData::Bit1
    end

    it 'should have a default value of 1' do
      expect(header.flags2_unicode).to eq 1
    end
  end

  describe 'flags2_nt_status' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags2_nt_status).to be_a BinData::Bit1
    end

    it 'should have a default value of 1' do
      expect(header.flags2_nt_status).to eq 1
    end
  end

  describe 'flags2_paging_io' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags2_paging_io).to be_a BinData::Bit1
    end
  end

  describe 'flags2_dfs' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags2_dfs).to be_a BinData::Bit1
    end
  end

  describe 'flags2_extended_security' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags2_extended_security).to be_a BinData::Bit1
    end
  end

  describe 'flags2_reparse_path' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags2_reparse_path).to be_a BinData::Bit1
    end
  end

  describe 'flags2_reserved1' do
    it 'should be a 3-bit field per the SMB spec' do
      expect(header.flags2_reserved1).to be_a BinData::Bit3
    end

    it 'should have a default value of 0' do
      expect(header.flags2_reserved1).to eq 0
    end
  end

  describe 'flags2_is_long_name' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags2_is_long_name).to be_a BinData::Bit1
    end
  end

  describe 'flags2_reserved2' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags2_reserved2).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(header.flags2_reserved2).to eq 0
    end
  end

  describe 'flags2_signature_required' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags2_signature_required).to be_a BinData::Bit1
    end
  end

  describe 'flags2_compressed' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags2_compressed).to be_a BinData::Bit1
    end
  end

  describe 'flags2_security_signature' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags2_security_signature).to be_a BinData::Bit1
    end
  end

  describe 'flags2_eas' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags2_eas).to be_a BinData::Bit1
    end
  end

  describe 'flags2_long_names' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(header.flags2_long_names).to be_a BinData::Bit1
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

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@endian)).to eq :little
  end
end