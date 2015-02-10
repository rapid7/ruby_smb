# Smb2

[![Build Status](https://travis-ci.org/jlee-r7/smb2.svg?branch=master)](https://travis-ci.org/jlee-r7/smb2)

A packet parsing and manipulation library for the SMB2 protocol.

See Microsoft's [[MS-SMB2]](http://msdn.microsoft.com/en-us/library/cc246482.aspx)

It supports authentication via NTLM using the [ruby ntlm gem](https://rubygems.org/gems/rubyntlm)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'smb2'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install smb2

## Usage

```ruby
sock = TCPSocket.new("192.168.100.140", 445)
neg = Smb2::Packet::NegotiateRequest.new(
  dialects: "\x02\x02".b,
)
nbss = [neg.length].pack("N")
sock.write(nbss + neg.to_s)
data = sock.read(36)
neg_response = Smb2::Packet::NegotiateResponse.new(data)

```

## Contributing

1. Fork it ( https://github.com/jlee-r7/smb2/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
