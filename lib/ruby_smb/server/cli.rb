require 'optparse'

module RubySMB
  class Server
    module Cli
      DEFAULT_OPTIONS = {
        allow_anonymous: true,
        allow_guests: false,
        domain: nil,
        username: 'RubySMB',
        password: 'password',
        share_name: 'home',
        smbv1: true,
        smbv2: true,
        smbv3: true
      }.freeze

      # Parse options from the command line. The resulting option hash is suitable for passing to {build}.
      #
      # @yield [options, parser] A block that can be used to update the built option parser.
      # @yieldparam [Hash<Symbol => >] options The options hash that should be assigned to.
      # @yieldparam [OptionParser] parser The built option parser.
      # @param [Hash] defaults Default option values to use.
      # @return [Hash<Symbol => >] The options hash.
      #   * :allow_anonymous [Boolean] Whether or not to allow anonymous authentication.
      #   * :allow_guest [Boolean] Whether or not to allow guest authentication.
      #   * :username [String] The username of the account to add for authentication.
      #   * :password [String] The password of the account to add for authentication.
      #   * :domain [String] The domain of the account to add for authentication.
      #   * :smbv1 [Boolean] Whether or not to enable SMBv1 dialects.
      #   * :smbv2 [Boolean] Whether or not to enable SMBv2 dialects.
      #   * :smbv3 [Boolean] Whether or not to enable SMBv3 dialects.
      #   * :share_name [String] The name of the share to add.
      def self.parse(defaults: {}, &block)
        defaults = DEFAULT_OPTIONS.merge(defaults)
        options = defaults.clone
        OptionParser.new do |parser|
          parser.on("--share SHARE", "The share name (default: #{defaults[:share_name]})") do |share|
            options[:share_name] = share
          end

          parser.on("--[no-]anonymous", "Allow anonymous access (default: #{defaults[:allow_anonymous]})") do |allow_anonymous|
            options[:allow_anonymous] = allow_anonymous
          end

          parser.on("--[no-]guests", "Allow guest accounts (default: #{defaults[:allow_guests]})") do |allow_guests|
            options[:allow_guests] = allow_guests
          end

          parser.on("--[no-]smbv1", "Enable or disable SMBv1 (default: #{defaults[:smbv1] ? 'Enabled' : 'Disabled'})") do |smbv1|
            options[:smbv1] = smbv1
          end

          parser.on("--[no-]smbv2", "Enable or disable SMBv2 (default: #{defaults[:smbv2] ? 'Enabled' : 'Disabled'})") do |smbv2|
            options[:smbv2] = smbv2
          end

          parser.on("--[no-]smbv3", "Enable or disable SMBv3 (default: #{defaults[:smbv3] ? 'Enabled' : 'Disabled'})") do |smbv3|
            options[:smbv3] = smbv3
          end

          parser.on("--username USERNAME", "The account's username (default: #{defaults[:username]})") do |username|
            if username.include?('\\')
              options[:domain], options[:username] = username.split('\\', 2)
            else
              options[:username] = username
            end
          end

          parser.on("--password PASSWORD", "The account's password (default: #{defaults[:password]})") do |password|
            options[:password] = password
          end

          block.call(options, parser) if block_given?
        end.parse!

        options
      end

      # Build a server instance from the specified options. The NTLM provider will be used for authentication.
      #
      # @param [Hash] options the options to use while building the server. See the return value of {parse} for a
      #   comprehensive list of keys.
      def self.build(options)
        ntlm_provider = RubySMB::Gss::Provider::NTLM.new(
          allow_anonymous: options[:allow_anonymous],
          allow_guests: options[:allow_guests]
        )
        ntlm_provider.put_account(options[:username], options[:password], domain: options[:domain])  # password can also be an NTLM hash

        server = RubySMB::Server.new(
          gss_provider: ntlm_provider,
          logger: :stdout
        )
        server.dialects.select! { |dialect| RubySMB::Dialect[dialect].family != RubySMB::Dialect::FAMILY_SMB1 } unless options[:smbv1]
        server.dialects.select! { |dialect| RubySMB::Dialect[dialect].family != RubySMB::Dialect::FAMILY_SMB2 } unless options[:smbv2]
        server.dialects.select! { |dialect| RubySMB::Dialect[dialect].family != RubySMB::Dialect::FAMILY_SMB3 } unless options[:smbv3]

        server
      end

      # Run the server forever. At least 1 SMB dialect must be enabled.
      #
      # @param [RubySMB::Server] server The server instance to run.
      # @param [#puts] out The stream to write standard output messages to.
      # @param [#puts] err The stream to write error messages to.
      def self.run(server, out: $stdout, err: $stderr)
        if server.dialects.empty?
          err.puts 'at least one version must be enabled'
          return
        end

        out.puts 'server is running'
        server.run do |server_client|
          out.puts 'received connection'
          true
        end
      end
    end
  end
end
