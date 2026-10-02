module RubySMB
  # Compatibility shims for the gems RubySMB builds on.
  module Compatibility
  end
end

# BinData rejects a field name when a method of that name is already defined on
# the struct class. The check in BinData::DSLMixin::DSLFieldValidator uses
# Module#method_defined? without the second argument, so it also matches methods
# inherited from ancestors such as Object, Kernel and Hash.
#
# That is too broad in practice. When a test suite loads a mocking library that
# adds helper methods to Object (rspec-mocks defines #stub on BasicObject when
# `config.mock_with :rspec` is used, mocha defines #stubs, and so on) before
# ruby_smb is required, perfectly valid BinData definitions start raising
#   SyntaxError: field 'stub' shadows an existing method
# even though no struct field actually shadows a method that the struct itself
# relies on. See https://github.com/rapid7/ruby_smb/issues/261.
#
# Field accessors are installed per instance with define_singleton_method, so an
# inherited method named like a field never gets in the way at runtime; only a
# method defined directly on the struct class is a genuine collision. Passing
# `false` to method_defined? restricts the check to methods defined directly on
# the class, which is the behaviour the guard is actually meant to enforce.
# Names that clash with Hash/BinData internals remain covered by the separate
# BinData::Struct::RESERVED list, so this does not loosen that protection.
if defined?(BinData::DSLMixin::DSLFieldValidator)
  module BinData
    module DSLMixin
      class DSLFieldValidator
        def name_shadows_method?(name)
          @the_class.method_defined?(name, false)
        end
      end
    end
  end
end
