require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileSystemInformation do

  describe '#name' do
    it 'maps constant names to their value' do
      expect(described_class.name(RubySMB::Fscc::FileSystemInformation::FILE_FS_VOLUME_INFORMATION)).to eq :FILE_FS_VOLUME_INFORMATION
    end

    it 'returns nil for values that do not exist' do
      expect(described_class.name(-1)).to be_nil
    end
  end
end
