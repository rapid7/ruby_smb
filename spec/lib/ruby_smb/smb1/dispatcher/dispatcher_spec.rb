require 'spec_helper'

module RubySMB
module SMB1
RSpec.describe Dispatcher do

  describe 'interface: +rw command' do

    context 'command given' do
      describe '#command' do
        it 'returns the command attribute' do
          command = double('command')
          dispatcher = Dispatcher.new command
          expect(dispatcher.command).to eql command
        end
      end

      describe '#command=' do
        it 'sets the command attribute' do
          command_current = double('command_current')
          command_new     = double('command_new')
          dispatcher      = Dispatcher.new command_current

          expect{ dispatcher.command = command_new }.to \
            change{ dispatcher.command }.to(command_new)
        end
      end
    end

    context 'command not given' do
      it 'raises an ArgumentError' do
        expect{Dispatcher.new}.to raise_error ArgumentError
      end
    end
  end

  describe '#transmit' do
    it 'sends the transmit command' do
      command    = double('command')
      dispatcher = Dispatcher.new command

      expect(command).to receive(:transmit)

      dispatcher.transmit
    end
  end

end
end
end
