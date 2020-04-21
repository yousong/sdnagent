module yunion.io/x/sdnagent

go 1.12

require (
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/coreos/go-iptables v0.4.5
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/digitalocean/go-openvswitch v0.0.0-20190515160856-1141932ed5cf
	github.com/fsnotify/fsnotify v1.4.7
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/protobuf v1.3.2
	github.com/hashicorp/hcl v0.0.0-20180404174102-ef8a98b0bbce // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/magiconair/properties v1.8.0 // indirect
	github.com/mgutz/ansi v0.0.0-20170206155736-9520e82c474b // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v0.0.0-20180715050151-f15292f7a699 // indirect
	github.com/onsi/ginkgo v1.8.0 // indirect
	github.com/onsi/gomega v1.5.0 // indirect
	github.com/pelletier/go-toml v1.2.0 // indirect
	github.com/pkg/errors v0.8.1
	github.com/spf13/afero v1.1.1 // indirect
	github.com/spf13/cast v1.2.0 // indirect
	github.com/spf13/cobra v0.0.3
	github.com/spf13/jwalterweatherman v0.0.0-20180109140146-7c0cea34c8ec // indirect
	github.com/spf13/pflag v1.0.3
	github.com/spf13/viper v1.0.2
	github.com/vishvananda/netlink v1.0.0
	golang.org/x/net v0.0.0-20191209160850-c0dbc17a3553
	google.golang.org/grpc v1.26.0
	gopkg.in/airbrake/gobrake.v2 v2.0.9 // indirect
	gopkg.in/gemnasium/logrus-airbrake-hook.v2 v2.1.2 // indirect
	gopkg.in/yaml.v2 v2.2.2
	yunion.io/x/log v0.0.0-20190629062853-9f6483a7103d
	yunion.io/x/onecloud v0.0.0-20200312033825-dfdfe1e872ac
	yunion.io/x/pkg v0.0.0-20200416145704-22c189971435
)

replace github.com/digitalocean/go-openvswitch v0.0.0-20190515160856-1141932ed5cf => github.com/yousong/go-openvswitch v0.0.0-20180721082006-96232eeb655d
