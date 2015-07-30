require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::AndXBlock do

  subject(:andx_block) { described_class.new }

  it { is_expected.to respond_to :andx_command }
  it { is_expected.to respond_to :andx_reserved }
  it { is_expected.to respond_to :andx_offset }

  describe 'defaults' do
    it 'sets andx_command to SMB_COM_NO_ANDX_COMMAND by default' do
      expect(andx_block.andx_command).to eq RubySMB::SMB1::COMMANDS[:SMB_COM_NO_ANDX_COMMAND]
    end

    it 'sets andx_reserved to 0 by default' do
      expect(andx_block.andx_reserved).to eq 0
    end

    it 'sets andx_offset to 0 by default' do
      expect(andx_block.andx_offset).to eq 0
    end
  end
end