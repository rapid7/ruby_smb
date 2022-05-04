require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileSystemInformation::FileFsAttributeInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileSystemInformation::FILE_FS_ATTRIBUTE_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :file_system_attributes }
  it { should respond_to :maximum_component_name_length }
  it { should respond_to :file_system_name_length }
  it { should respond_to :file_system_name }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the file system attributes in a struct field' do
    expect(struct.file_system_attributes).to be_a BinData::Struct
  end

  it 'tracks the maximum component name length in a Int32 field' do
    expect(struct.maximum_component_name_length).to be_a BinData::Int32le
  end

  it 'tracks the file system name length in a Uint32 field' do
    expect(struct.file_system_name_length).to be_a BinData::Uint32le
  end

  it 'tracks the file system name in a String16 field' do
    expect(struct.file_system_name).to be_a RubySMB::Field::String16
  end

  it 'tracks the length of the file_system_name field' do
    struct.file_system_name = 'NTFS'
    expect(struct.file_system_name_length).to eq struct.file_system_name.do_num_bytes
  end

  it 'automatically encodes the file system name in UTF-16LE' do
    name = 'NTFS'
    struct.file_system_name = name
    expect(struct.file_system_name.force_encoding('utf-16le')).to eq name.encode('utf-16le')
  end
end
