# Ruby-LXC

## Introduction

Ruby-LXC is a Ruby binding for liblxc. It allows the creation and management
of Linux Containers from Ruby scripts.


## Build and installation

Currently the binding is developed and tested against liblxc 1.0.0 build. To build ruby-lxc you need
- ubuntu 14.04
- lxc ipackage
```sh
sudo apt-get install lxc liblxc0 lxc-dev
```

- Build essential for compiling the bindings
```sh
sudo apt-get install build-essential
```

- Clone this repository and run the commands below (assuming you have bundler).
```sh
bundle install
bundle exec rake compile
gem install pkg/ruby-lxc-0.1.0.gem
```
or just add this to your ```Gemfile```
```ruby
gem "ruby-lxc", github: "andrenth/ruby-lxc"
```

## Usage

- Container lifecycle management (create, start, stop and destroy containers)
```ruby
c = LXC::Container.new('foo')
c.create('ubuntu') # create a container named foo with ubuntu template
c.start
c.stop
c.destroy
```

- Additional state changing operations (freezing, unfreezing and cloning containers)
```ruby
c.freeze
c.unfreeze
c.reboot
c.shutdown
```

- Clone a container
```ruby
c.clone('bar') # clone foo into bar. parent container has to bee in freeze or stopped state.
```

- Wait for a state change
```ruby
c.wait('STOPPED', 10) # wait till container goes to STOPPED state, else timeout after 10 seconds
```

