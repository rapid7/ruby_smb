require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileRenameInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileInformation::FILE_ID_FULL_DIRECTORY_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :replace_if_exists }
  it { should respond_to :reserved_0 }
  it { should respond_to :reserved_1 }
  it { should respond_to :reserved_2 }
  it { should respond_to :root_firectory }
  it { should respond_to :file_name_length }
  it { should respond_to :file_name }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe 'reading in from a blob' do
    it 'uses the file_name_length to know when to stop reading' do
      name = 'Hello_world.txt'
      struct.file_name = name
      blob = struct.to_binary_s
      blob << 'AAAA'
      new_from_blob = described_class.read(blob)
      expect(new_from_blob.file_name).to eq name
    end
  end

  describe '#replace_if_exists' do
    it 'is a 8-bit field' do
      expect(struct.replace_if_exists).to be_a BinData::Uint8
    end
  end

  describe '#root_firectory' do
    it 'is a 64-bit field' do
      expect(struct.root_firectory).to be_a BinData::Uint64le
    end

    it 'should have a default value of 0' do
      expect(struct.root_firectory).to eq 0
    end
  end

  describe '#file_name_length' do
    it 'is a 32-bit field' do
      expect(struct.file_name_length).to be_a BinData::Uint32le
    end

    it 'should have a default value of 0' do
      expect(struct.file_name_length).to eq 0
    end

    it 'tracks the length of the file_name field' do
      struct.file_name = 'Hello.txt'
      expect(struct.file_name_length).to eq struct.file_name.do_num_bytes
    end
  end

  describe '#file_name' do
    it 'is a string field' do
      expect(struct.file_name).to be_a BinData::String
    end
  end
end
