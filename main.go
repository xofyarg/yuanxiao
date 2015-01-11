package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"repo.anb.im/goutil/log"
	"repo.anb.im/goutil/option"

	"repo.anb.im/yuanxiao/source"
)

func main() {
	parseArgs()
	go setupSignals()

	if err := serverInit(); err != nil {
		log.Fatal("server init: %s", err)
		os.Exit(1)
	}

	if err := serverStart(); err != nil {
		log.Fatal("cannot start server: %s", err)
		os.Exit(1)
	}
}

func parseArgs() {
	// set command line only arguments
	option.CliOnly([]string{"config.path", "config.generate", "source.list"})
	option.String("config.path", "yuanxiao.conf",
		"Path to config file. Default is yuanxiao.conf at current working directory.")
	option.Bool("config.generate", false,
		"Output all support options with their default values as a config file to stdout.")
	option.Bool("source.list", false,
		"Enabled source and their order. Builtin sources can be accquired by source.list.")

	// normal options
	option.String("server.addr", ":53",
		"Address to bind. Default is udp port 53 on all interfaces.")
	option.Int("server.cachesize", 1024,
		"Query cache size for server.")

	option.String("log.level", "info",
		"Verbose level. Supported levels: fatal, warn, info, debug")

	option.String("source.enable", "",
		"Enabled source and their order. Builtin sources can be accquired by source.list.")

	option.String("source.plain.path", "",
		"Path to the root of zone file or directory.")
	option.String("source.relay.upstream", "",
		"Upstream servers for dns relay, use ',' to split multiple values.")
	option.String("source.relay.timeout", "2s",
		"Query timeout for upstream servers.")
	option.String("source.relay.delay", "0",
		"Query delay. Make sure you know what it is before set it to a non-zero value.")
	option.String("source.etcd.machines", "",
		"List of etcd hosts.")
	option.String("source.etcd.cache.size", "64",
		"Cache size for item get from etcd.")
	option.String("source.etcd.cache.ttl", "60s",
		"How long will a item be valid after get from etcd.")

	// first, parse args to find the config path
	if err := option.Parse(); err != nil {
		log.Fatal("fail to parse options: %s", err)
		os.Exit(1)
	}

	if option.GetBool("config.generate") {
		fmt.Printf("%s", option.Defaults())
		os.Exit(0)
	}

	if option.GetBool("source.list") {
		fmt.Printf("Support sources:\n")
		for _, s := range source.Sources {
			fmt.Printf("  %s\n", s)
		}
		os.Exit(0)
	}

	// try to load config, ignore error
	if err := option.LoadConfig(option.GetString("config.path")); err != nil {
		log.Warn("fail to parse options: %s", err)
	}

	// parse cli args again to overwrite config value
	if err := option.Parse(); err != nil {
		log.Fatal("fail to parse options: %s", err)
		os.Exit(1)
	}

	log.SetLevel(option.GetString("log.level"))

}

func setupSignals() {
	sig := make(chan os.Signal, 5)
	signal.Notify(sig, syscall.SIGHUP)

	for s := range sig {
		switch s {
		case syscall.SIGHUP:
			log.Info("server reloading")
			if err := serverReload(); err != nil {
				log.Warn("server reload failed: %s", err)
			}
		default:
		}
	}
}