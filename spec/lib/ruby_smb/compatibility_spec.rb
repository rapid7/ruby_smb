require 'spec_helper'

RSpec.describe 'BinData field name compatibility (issue #261)' do
  # Regression coverage for
  # https://github.com/rapid7/ruby_smb/issues/261
  #
  # Loading a mocking library (rspec-mocks via `config.mock_with :rspec`) adds a
  # #stub helper to Object before ruby_smb is required. BinData's field-name
  # guard used method_defined? without restricting it to the struct class, so it
  # picked up that inherited method and refused otherwise-valid field names such
  # as :stub (RubySMB::Dcerpc::Request actually has a :stub field).

  context 'when an inherited method shares a name with a BinData field' do
    before do
      # Simulate what rspec-mocks/mocha do: define a helper method on Object so
      # that every class, including a fresh BinData struct, inherits it.
      Object.send(:define_method, :inherited_helper_261) { :from_object }
    end

    after do
      Object.send(:remove_method, :inherited_helper_261)
    end

    it 'allows the field to be defined without raising' do
      expect(Object.method_defined?(:inherited_helper_261)).to be true

      expect do
        Class.new(BinData::Record) do
          uint8 :inherited_helper_261
        end
      end.not_to raise_error
    end
  end

  context 'when a field name shadows a method defined directly on the struct' do
    it 'still raises, so the genuine guard is preserved' do
      expect do
        Class.new(BinData::Record) do
          def direct_method_261; end
          uint8 :direct_method_261
        end
      end.to raise_error(/shadows an existing method/)
    end
  end

  context 'when a field name collides with a BinData reserved name' do
    it 'still raises, so the RESERVED guard is preserved' do
      expect do
        Class.new(BinData::Record) do
          uint8 :keys # Hash#keys, part of BinData::Struct::RESERVED
        end
      end.to raise_error(/reserved name/)
    end
  end
end
