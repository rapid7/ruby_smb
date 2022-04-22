require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileSystemInformation::FileFsVolumeInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileSystemInformation::FILE_FS_VOLUME_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :volume_creation_time }
  it { should respond_to :volume_serial_number }
  it { should respond_to :volume_label_length }
  it { should respond_to :supports_objects }
  it { should respond_to :volume_label }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the volume creation time in a FileTime field' do
    expect(struct.volume_creation_time).to be_a RubySMB::Field::FileTime
  end

  it 'tracks the volume serial number in a Uint32 field' do
    expect(struct.volume_serial_number).to be_a BinData::Uint32le
  end

  it 'tracks the volume label length in a Uint32 field' do
    expect(struct.volume_label_length).to be_a BinData::Uint32le
  end

  it 'tracks if it supports objects in a Uint8 field' do
    expect(struct.supports_objects).to be_a BinData::Uint8
  end

  it 'tracks the volume label in a String16 field' do
    expect(struct.volume_label).to be_a RubySMB::Field::String16
  end

  it 'tracks the length of the volume_label field' do
    struct.volume_label = 'NTFS'
    expect(struct.volume_label_length).to eq struct.volume_label.do_num_bytes
  end

  it 'automatically encodes the file system name in UTF-16LE' do
    name = 'NTFS'
    struct.volume_label = name
    expect(struct.volume_label.force_encoding('utf-16le')).to eq name.encode('utf-16le')
  end
end
