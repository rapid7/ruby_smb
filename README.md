# Smb2

[![Build Status](https://travis-ci.org/rapid7/ruby_smb.svg?branch=master)](https://travis-ci.org/rapid7/ruby_smb)
[![Code Climate](https://codeclimate.com/github/rapid7/ruby_smb.png)](https://codeclimate.com/github/rapid7/ruby_smb)
[![PullReview stats](https://www.pullreview.com/github/rapid7/ruby_smb/badges/master.svg)](https://www.pullreview.com/github/rapid7/ruby_smb/reviews/master)
[![Coverage Status](https://coveralls.io/repos/rapid7/ruby_smb/badge.svg?branch=master&service=github)](https://coveralls.io/github/rapid7/ruby_smb?branch=master)

A packet parsing and manipulation library for the SMB2 protocol.

See Microsoft's [[MS-SMB2]](http://msdn.microsoft.com/en-us/library/cc246482.aspx)

It supports authentication via NTLM using the [ruby ntlm gem](https://rubygems.org/gems/rubyntlm)

## Installation

This gem has not yet been released, but when it is, do this:

Add this line to your application's Gemfile:

```ruby
gem 'smb2'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install smb2

## Usage

### Using the `Client` class

```ruby
dispatcher = RubySMB::Dispatcher::Socket.connect("192.168.100.140", 445)
client = RubySMB::Smb2::Client.new(
  dispatcher: dispatcher,
  username:"administrator",
  password:"P@ssword1",
  domain:"asdfasdf"
)
client.negotiate
client.authenticate

tree = client.tree_connect("\\\\#{dispatcher.socket.remote_address.ip_address}\\Users")
```

Now you can open files on the connected share. `Tree#create` is intended
to behave like Ruby's
[File.open](http://ruby-doc.org/core-2.2.0/File.html#method-c-open):
```ruby
# read/write by default
file = tree.create("Public\\file.txt")
file.read # => <full contents of file.txt>
file.write("\nAppend a new line to file.txt")
```

Or with a block, the file will be closed when the block returns:
```ruby
data = tree.create("Public\\file.txt") { |file|
  file.read
}
```

### Making packets manually

```ruby
sock = TCPSocket.new("192.168.100.140", 445)
neg = Smb2::Packet::NegotiateRequest.new(
  # This is necessary until I can figure out how to set a default for
  # `rest` fields
  dialects: "\x02\x02".force_encoding("binary"),
)
nbss = [neg.length].pack("N")
sock.write(nbss + neg.to_s)
# Grab NBSS size
size = sock.read(4).unpack("N").first
data = sock.read(size)
neg_response = Smb2::Packet::NegotiateResponse.new(data)

```

## Developer tips
You'll want to have Wireshark and perhaps a tool like Impacket (which provides a small SMB client in one of its examples) installed to help with your work:

### Wireshark
- `sudo apt-get install wireshark`
- `sudo dpkg-reconfigure wireshark-common`
- `sudo addgroup wireshark`
- `sudo usermod -a -G wireshark <USERNAME>`

### Impacket
- `sudo apt-get install python-setuptools`
- `sudo easy_install pyasn1 pycrypto`
- Download from GitHub (https://github.com/coresecurity/impacket)
- `sudo python setup.py install`
- `cd examples && python smbclient.py <USER>:<PASS>@<WINDOWS HOST IP>`



## License

ruby_smb is released under a 3-clause BSD license. See [LICENSE.txt](LICENSE.txt) for full text.


## Contributing

1. Fork it ( https://github.com/rapid7/smb2/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
