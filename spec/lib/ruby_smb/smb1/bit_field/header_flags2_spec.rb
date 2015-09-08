RSpec.describe RubySMB::SMB1::BitField::HeaderFlags2 do
  subject(:flags2) { described_class.new }

  it { is_expected.to respond_to :unicode }
  it { is_expected.to respond_to :nt_status }
  it { is_expected.to respond_to :paging_io }
  it { is_expected.to respond_to :dfs }
  it { is_expected.to respond_to :extended_security }
  it { is_expected.to respond_to :reparse_path }
  it { is_expected.to respond_to :reserved1 }
  it { is_expected.to respond_to :is_long_name }
  it { is_expected.to respond_to :reserved2 }
  it { is_expected.to respond_to :signature_required }
  it { is_expected.to respond_to :compressed }
  it { is_expected.to respond_to :security_signature }
  it { is_expected.to respond_to :eas }
  it { is_expected.to respond_to :long_names }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@endian)).to eq :little
  end

  describe 'unicode' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.unicode).to be_a BinData::Bit1
    end

    it 'should have a default value of 1' do
      expect(flags2.unicode).to eq 1
    end
  end

  describe 'nt_status' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.nt_status).to be_a BinData::Bit1
    end

    it 'should have a default value of 1' do
      expect(flags2.nt_status).to eq 1
    end
  end

  describe 'paging_io' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.paging_io).to be_a BinData::Bit1
    end
  end

  describe 'dfs' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.dfs).to be_a BinData::Bit1
    end
  end

  describe 'extended_security' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.extended_security).to be_a BinData::Bit1
    end
  end

  describe 'reparse_path' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.reparse_path).to be_a BinData::Bit1
    end
  end

  describe 'reserved1' do
    it 'should be a 3-bit field per the SMB spec' do
      expect(flags2.reserved1).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(flags2.reserved1).to eq 0
    end
  end

  describe 'is_long_name' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.is_long_name).to be_a BinData::Bit1
    end
  end

  describe 'reserved2' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.reserved2).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(flags2.reserved2).to eq 0
    end
  end

  describe 'signature_required' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.signature_required).to be_a BinData::Bit1
    end
  end

  describe 'compressed' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.compressed).to be_a BinData::Bit1
    end
  end

  describe 'security_signature' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.security_signature).to be_a BinData::Bit1
    end
  end

  describe 'eas' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.eas).to be_a BinData::Bit1
    end
  end

  describe 'long_names' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.long_names).to be_a BinData::Bit1
    end
  end
end
