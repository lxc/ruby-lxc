require 'rspec'
require 'lxc'

module LXCSpecHelper

  extend self

  def spawn_test_container
    validate_root!
    container.create('ubuntu') unless container.defined?
  end

  def container_name
    'test'
  end

  def container
    LXC::Container.new(container_name)
  end

  def destroy_test_container
    validate_root!
    container.destroy
  end

  def validate_root!
    if Process::Sys::geteuid != 0
      raise 'This test must be ran as root'
    end
  end
end

RSpec.configure do |config|

  config.include LXCSpecHelper

  config.before(:suite) do
    LXCSpecHelper.spawn_test_container
  end

  config.after(:suite) do
    LXCSpecHelper.destroy_test_container
  end
end
