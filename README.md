# Smb2

[![Build Status](https://travis-ci.org/rapid7/smb2.svg?branch=master)](https://travis-ci.org/rapid7/smb2)

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
sock = TCPSocket.new("192.168.100.140", 445)
c = Smb2::Client.new(
  socket: sock,
  username:"administrator",
  password:"P@ssword1",
  domain:"asdfasdf"
)
c.negotiate
c.authenticate
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

## Contributing

1. Fork it ( https://github.com/jlee-r7/smb2/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
