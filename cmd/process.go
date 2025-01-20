// Copyright 2022 Leon Ding <ding@ibyte.me> https://wiredkv.github.io

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// wired kv process logic code
package cmd

import (
	_ "embed"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/auula/wiredkv/clog"
	"github.com/auula/wiredkv/conf"
	"github.com/auula/wiredkv/server"
	"github.com/auula/wiredkv/utils"
	"github.com/auula/wiredkv/vfs"
	"github.com/fatih/color"
)

const (
	version = "v0.1.1"
	website = "https://wiredkv.github.io"
)

var (
	//go:embed banner.txt
	logo      string
	greenFont = color.New(color.FgHiRed)
	banner    = greenFont.Sprintf(logo, version, website)
	daemon    = false
)

// 初始化全局需要使用的组件
// 解析命令行输入的参数，默认命令行参数优先级最高，但是相对于能设置参数比较少
func init() {
	fmt.Println(banner)
	fl := parseFlags()

	if conf.HasCustom(fl.config) {
		err := conf.Load(fl.config, conf.Settings)
		if err != nil {
			clog.Failed(err)
		}
		clog.Info("Loading custom config file was successfully")
	}

	if fl.debug {
		conf.Settings.Debug, clog.IsDebug = fl.debug, fl.debug
	}

	// 命令行传入的密码优先级最高
	if fl.auth != conf.Default.Password {
		conf.Settings.Password = fl.auth
	} else {
		// 如果命令行没有传入密码，系统随机生成一串 20 位的密码
		conf.Settings.Password = utils.RandomString(20)
		clog.Infof("The default password is: %s", conf.Settings.Password)
	}

	if fl.path != conf.Default.Path {
		conf.Settings.Path = fl.path
	}

	if fl.port != conf.Default.Port {
		conf.Settings.Port = fl.port
	}

	clog.Debug(conf.Settings)

	var err error = nil
	// 验证命令参入的参数，即使有默认配置，命令行参数不受约束
	err = conf.Vaildated(conf.Settings)
	if err != nil {
		clog.Failed(err)
	}

	err = clog.SetOutput(conf.Settings.LogPath)
	if err != nil {
		clog.Failed(err)
	}

	clog.Info("Logging output initialized successfully")
}

func StartApp() {
	if daemon {
		runAsDaemon()
	} else {
		runServer()
	}
}

func runAsDaemon() {
	args := utils.SplitArgs(utils.TrimDaemon(os.Args))
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = os.Environ()

	err := cmd.Start()
	if err != nil {
		clog.Failed(err)
	}

	clog.Infof("Daemon launched PID: %d", cmd.Process.Pid)
	os.Exit(0)
}

func runServer() {
	hts, err := server.New(&server.Options{
		Port: conf.Settings.Port,
		Auth: conf.Settings.Password,
	})
	if err != nil {
		clog.Failed(err)
	}

	fss, err := vfs.OpenFS(&vfs.Options{
		FsPerm:    conf.FsPerm,
		Path:      conf.Settings.Path,
		Threshold: conf.Settings.Region.Threshold,
	})
	if err != nil {
		clog.Failed(err)
	}

	if conf.Settings.IsCompressionEnabled() {
		// 设置文件数据使用 Snappy 压缩算法
		fss.SetCompressor(vfs.SnappyCompressor)
		clog.Info("Snappy compression activated successfully")
	}

	if conf.Settings.IsRegionGCEnabled() {
		fss.StartRegionGC(conf.Settings.RegionGCInterval())
		clog.Info("Region compression activated successfully")
	}

	if len(conf.Settings.AllowIP) > 0 {
		hts.SetAllowIP(conf.Settings.AllowIP)
		clog.Info("Setting whitelist IP successfully")
	}

	hts.SetupFS(fss)
	clog.Info("File system setup completed successfully")

	go func() {
		err := hts.Startup()
		if err != nil {
			clog.Failed(err)
		}
	}()

	// 延迟输出正常休息，因为上面的 Startup 方法在正常情况下是一个阻塞方法
	time.Sleep(500 * time.Millisecond)
	clog.Infof("HTTP server started at http://%s:%d 🚀", hts.IPv4(), hts.Port())

	// Keep the main process alive
	select {}
}

type flags struct {
	auth   string
	port   int
	path   string
	config string
	debug  bool
}

func parseFlags() (fl *flags) {
	fl = new(flags)
	flag.StringVar(&fl.auth, "auth", conf.Default.Password, "--auth the server authentication password.")
	flag.StringVar(&fl.path, "path", conf.Default.Path, "--path the data storage directory.")
	flag.BoolVar(&fl.debug, "debug", conf.Default.Debug, "--debug enable debug mode.")
	flag.StringVar(&fl.config, "config", "", "--config the configuration file path.")
	flag.IntVar(&fl.port, "port", conf.Default.Port, "--port the HTTP server port.")
	flag.BoolVar(&daemon, "daemon", false, "--daemon run with a daemon.")
	flag.Parse()
	return
}
