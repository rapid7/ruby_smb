module RubySMB
  class Client
    module Winreg

      def connect_to_winreg(host)
        share = "\\\\#{host}\\IPC$"
        tree = @tree_connects.find {|tree| tree.share == share}
        tree = tree_connect(share) unless tree
        named_pipe = tree.open_pipe(filename: "winreg", write: true, read: true)
        if block_given?
          res = yield named_pipe
          named_pipe.close
          res
        else
          named_pipe
        end
      end

      def has_registry_key?(host, key)
        connect_to_winreg(host) do |named_pipe|
          named_pipe.has_registry_key?(key)
        end
      end

      def read_registry_key_value(host, key, value_name)
        connect_to_winreg(host) do |named_pipe|
          named_pipe.read_registry_key_value(key, value_name)
        end
      end

      def enum_registry_key(host, key)
        connect_to_winreg(host) do |named_pipe|
          named_pipe.enum_registry_key(key)
        end
      end

      def enum_registry_values(host, key)
        connect_to_winreg(host) do |named_pipe|
          named_pipe.enum_registry_values(key)
        end
      end

      def get_key_security_descriptor(host, key, security_information = RubySMB::Field::SecurityDescriptor::OWNER_SECURITY_INFORMATION)
        connect_to_winreg(host) do |named_pipe|
          named_pipe.get_key_security_descriptor(key, security_information)
        end
      end

      def set_key_security_descriptor(host, key, security_descriptor, security_information = RubySMB::Field::SecurityDescriptor::OWNER_SECURITY_INFORMATION)
        connect_to_winreg(host) do |named_pipe|
          named_pipe.set_key_security_descriptor(key, security_descriptor, security_information)
        end
      end

    end
  end
end

