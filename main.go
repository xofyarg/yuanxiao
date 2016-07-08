package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.papla.net/goutil/log"
	"go.papla.net/goutil/option"

	"go.papla.net/yuanxiao/source"
)

func main() {
	parseArgs()
	go setupSignals()

	if addr := option.GetString("server.pprof.addr"); addr != "" {
		go func() {
			err := http.ListenAndServe(addr, nil)
			log.Warnf("cannot start pprof server: %s", err)
		}()
	}

	if err := serverInit(); err != nil {
		log.Fatalf("server init: %s", err)
		os.Exit(1)
	}

	if err := serverStart(); err != nil {
		log.Fatalf("cannot start server: %s", err)
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

	// server options
	option.String("server.addr", ":53",
		"Address to bind. Default is udp port 53 on all interfaces.")
	option.Int("server.cache.size", 1024,
		"Query cache size for server. 0 to disable cache, and -1 for unlimit size.")
	option.Duration("server.cache.timeout", 1*time.Minute, "Cache entry timeout for server.")
	option.String("server.pprof.addr", "", "http address for pprof, leave blank to disable.")

	// log options
	option.String("log.level", "info",
		"Verbose level. Supported levels: fatal, warn, info, debug")

	// source options
	// NOTE: all source options should be in string type to forward to
	// sources
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
		log.Fatalf("fail to parse options: %s", err)
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
		log.Warnf("fail to parse options: %s", err)
	}

	// parse cli args again to overwrite config value
	if err := option.Parse(); err != nil {
		log.Fatalf("fail to parse options: %s", err)
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
			log.Infof("server reloading")
			if err := serverReload(); err != nil {
				log.Warnf("server reload failed: %s", err)
			}
		default:
		}
	}
}
