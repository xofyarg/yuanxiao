# yuanxiao

A flexible DNS server for small facilities.

# Overview

The motivation of writing yuanxiao is to cover HA(High Availability)
at domain name level. It is built for SREs who want to use DNS to
dispatch service at top level.It is designed to be extensible, easy to
deploy. Users can build tools on it to adapt their application
scenarios.

The DNS records are set to different kind of sources which are tried
one after another until one success. Using a combination of several
sources with a specific order can achieve multiple purpose.

# Installation

To build yuanxiao, you need a working go compiler, then just go-get it:
```shell
go get repo.anb.im/yuanxiao
```
Like other golang program, you'll get a single binary ready to run.

# Usage

After deploy, first thing to do is to generate a sample configuration
file by running:

```shell
/path/to/yuanxiao -config.generate > /etc/yuanxiao.conf
```

You can change the location of config file as your wish. The
descriptions for all the options are include in that file.

## Source

Source is an abstract database for yuanxiao to query for answers.
Three sources are currently supported: plain, etcd, relay.

### source: plain

A simple file or a directory of files which have the format of BIND
[zone file](http://en.wikipedia.org/wiki/Zone_file). Hidden files are
ignored while parsing.

### source: etcd

Use etcd as its backend. Domain names need to be splited into labels
and saved in reverse order. The values can be read from a zone file
syntax as the plain source. Records are add by using the _CREAT_
command of etcd. For example, we have two domains in etcd, both have a
A record:
```
foo.com.     30 A 1.1.1.1
www.bar.com. 30 A 2.2.2.2
```

in etcd, they should be saved in this format

```shell
curl -s 'http://localhost:2379/v2/keys?recursive=true' | python -m json.tool
{
    "action": "get",
    "node": {
	"createdIndex": 7,
	"dir": true,
	"modifiedIndex": 7,
	"nodes": [
	    {
		"createdIndex": 21,
		"dir": true,
		"key": "/com",
		"modifiedIndex": 21,
		"nodes": [
		    {
			"createdIndex": 21,
			"dir": true,
			"key": "/com/foo",
			"modifiedIndex": 21,
			"nodes": [
			    {
				"createdIndex": 24,
				"key": "/com/foo/21",
				"modifiedIndex": 24,
				"value": " 30 A 1.1.1.1"
			    }
			]
		    },
		    {
			"createdIndex": 22,
			"dir": true,
			"key": "/com/bar",
			"modifiedIndex": 22,
			"nodes": [
			    {
				"createdIndex": 22,
				"dir": true,
				"key": "/com/bar/www",
				"modifiedIndex": 22,
				"nodes": [
				    {
					"createdIndex": 23,
					"key": "/com/bar/www/22",
					"modifiedIndex": 23,
					"value": " 30 A 2.2.2.2"
				    }
				]
			    }
			]
		    }
		]
	    }
	]
    }
}
```

### source: relay

A proxy to relay the request to one or several upstream recursive
servers.
