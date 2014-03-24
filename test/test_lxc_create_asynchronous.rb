$:.unshift File.expand_path(File.join(File.dirname(__FILE__), 'lib'))

require 'test/unit'
require 'lxc'
require 'test_helpers'

class TestLXCCreateAsynchronous < Test::Unit::TestCase
  include TestHelpers

  def setup
    if Process::Sys::geteuid != 0
      raise 'This test must be ran as root'
    end
    @name = 'test_async_create'
    container = LXC::Container.new(@name)
    container.destroy if container.defined?
  end

  def test_create_allows_ruby_to_continue
    c = LXC::Container.new(@name)
    assert_long_running_function_does_not_block_ruby do
      c.create('ubuntu')
    end
  end
end
