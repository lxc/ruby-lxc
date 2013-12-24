$:.unshift File.expand_path(File.join(File.dirname(__FILE__), 'lib'))

require 'test/unit'
require 'lxc'
require 'timeout'

class TestLXCClassMethods < Test::Unit::TestCase
  def setup
    if Process::Sys::geteuid != 0
      raise 'This test must be ran as root'
    end
    @name = 'test'
    @container = LXC::Container.new(@name)
    @container.create('ubuntu') unless @container.defined?
  end

  def test_list_containers
    assert_equal([@name], LXC.list_containers)
  end

  def test_arch_to_personality
    assert_equal(:linux32, LXC.arch_to_personality('x86'))
    assert_equal(:linux, LXC.arch_to_personality('x86_64'))
  end
end
