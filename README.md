# Ruby-LXC

[![Build Status](https://travis-ci.org/lxc/ruby-lxc.svg?branch=master)](https://travis-ci.org/lxc/ruby-lxc)

## Introduction

Ruby-LXC is a Ruby binding for liblxc. It allows the creation and management
of Linux Containers from Ruby scripts.

## Build and installation

Assuming a current installation of LXC is available, to install Ruby-LXC
simply run the commands below

```sh
sudo apt-get install ruby-dev lxc-dev

bundle install
bundle exec rake compile
bundle exec rake gem
gem install pkg/ruby-lxc-1.2.0.gem
```
or just add this to your ```Gemfile```
```ruby
gem "ruby-lxc", github: "lxc/ruby-lxc", require: "lxc"
```

## Usage

- Container lifecycle management (create, start, stop and destroy containers)
```ruby
require 'lxc'
c = LXC::Container.new('foo')
c.create('ubuntu') # create a container named foo with ubuntu template
c.start
# attach to a running container
c.attach do
  LXC.run_command('ifconfig eth0')
end
c.stop
c.destroy
```

- Container inspection
```ruby
c.name
c.config_path
c.config_item('lxc.cap.drop')
c.cgroup_item('memory.limit_in_bytes')
c.init_pid
c.interfaces
c.ip_addresses
c.state
```

- Additional state changing operations (freezing, unfreezing and cloning
containers)
```ruby
c.freeze
c.unfreeze
c.reboot
c.shutdown
```

- Clone a container
```ruby
# clone foo into bar. Parent container has to be frozen or stopped.
clone = c.clone('bar')
```

- Wait for a state change
```ruby
# wait until container goes to STOPPED state, else timeout after 10 seconds
c.wait(:stopped, 10)
```

Check the provided rdoc documentation for a full list of methods. You can
generate it running
```sh
rake rdoc
```
