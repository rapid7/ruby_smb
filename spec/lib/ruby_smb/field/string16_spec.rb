RSpec.describe RubySMB::Field::String16 do
  subject(:field) { described_class.new }

  it 'is a BinData::String' do
    expect(field).to be_a BinData::String
  end

  it 'converts to utf-16le when assigning a String' do
    expect(field.assign('Test'.encode('ASCII-8BIT')).encoding).to be Encoding::UTF_16LE
  end

  it 'makes sure snapshot returns a utf-16le string' do
    field.new('Test'.encode('ASCII-8BIT'))
    expect(field.snapshot.encoding).to be Encoding::UTF_16LE
  end

  it 'makes sure read operation returns a utf-16le string' do
    field.read('Test'.encode('ASCII-8BIT'))
    expect(field.snapshot.encoding).to be Encoding::UTF_16LE
  end

end
