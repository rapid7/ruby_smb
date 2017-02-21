# RubySMB

[![Build Status](https://travis-ci.org/rapid7/ruby_smb.svg?branch=master)](https://travis-ci.org/rapid7/ruby_smb)
[![Code Climate](https://codeclimate.com/github/rapid7/ruby_smb.png)](https://codeclimate.com/github/rapid7/ruby_smb)
[![Coverage Status](https://coveralls.io/repos/rapid7/ruby_smb/badge.svg?branch=master&service=github)](https://coveralls.io/github/rapid7/ruby_smb?branch=master)

A packet parsing and manipulation library for the SMB family of protocols.

See Microsoft's [[MS-SMB2]](http://msdn.microsoft.com/en-us/library/cc246482.aspx)

It supports authentication via NTLM using the [ruby ntlm gem](https://rubygems.org/gems/rubyntlm)

## Installation

This gem has not yet been released, but when it is, do this:

Add this line to your application's Gemfile:

```ruby
gem 'ruby_smb'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ruby_smb

## Usage

Updated Usage Docs coming soon

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

`ruby_smb` is released under a 3-clause BSD license. See [LICENSE.txt](LICENSE.txt) for full text.


## Contributing

1. Fork it ( https://github.com/rapid7/smb2/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
