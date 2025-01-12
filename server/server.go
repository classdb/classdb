package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/auula/wiredkv/clog"
	"github.com/auula/wiredkv/vfs"
)

var (
	// ipv4 return local IPv4 address
	ipv4    string = "127.0.0.1"
	storage *vfs.LogStructuredFS
)

const (
	minPort = 1024
	maxPort = 1 << 16
	timeout = time.Second * 3
)

func init() {
	// 初始化的本地 IPv4 地址
	interfaces, err := net.Interfaces()
	if err != nil {
		clog.Errorf("get local IPv4 address failed: %s", err)
	}

	for _, face := range interfaces {
		adders, err := face.Addrs()
		if err != nil {
			clog.Errorf("get local IPv4 address failed: %s", err)
		}

		for _, addr := range adders {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					ipv4 = ipNet.IP.String()
				}
			}
		}
	}
}

type HttpServer struct {
	s      *http.Server
	closed int32
	port   int
}

type Options struct {
	Port int
	Auth string
	// certs *tls.Config
}

// New 创建一个新的 HTTP 服务器
func New(opt *Options) (*HttpServer, error) {
	if opt.Port < minPort || opt.Port > maxPort {
		return nil, errors.New("HTTP server port illegal")
	}

	if opt.Auth != "" {
		authPassword = opt.Auth
	}

	hs := HttpServer{
		s: &http.Server{
			Handler:      root,
			Addr:         net.JoinHostPort(ipv4, strconv.Itoa(opt.Port)),
			WriteTimeout: timeout,
			ReadTimeout:  timeout,
		},
		port:   opt.Port,
		closed: 0,
	}

	// 开启 HTTP Keep-Alive 长连接
	hs.s.SetKeepAlivesEnabled(true)
	atomic.StoreInt32(&hs.closed, 0)

	return &hs, nil
}

func (hs *HttpServer) SetupFS(fss *vfs.LogStructuredFS) {
	storage = fss
}

func (hs *HttpServer) Port() int {
	return hs.port
}

// IPv4 return local IPv4 address
func (hs *HttpServer) IPv4() string {
	return ipv4
}

// Startup blocking goroutine
func (hs *HttpServer) Startup() error {
	if hs.closed == 1 {
		return errors.New("http server has started")
	}
	if storage == nil {
		return errors.New("file storage system is not initialized")
	}

	atomic.StoreInt32(&hs.closed, 1)

	// 这个函数是一个阻塞函数
	err := hs.s.ListenAndServe()
	if err != nil {
		return fmt.Errorf("failed to start http api server :%w", err)
	}

	return hs.s.ListenAndServe()
}

func (hs *HttpServer) Shutdown() error {
	if hs.closed == 0 {
		return errors.New("http server not started")
	}

	// 先关闭 http 服务器停止接受数据请求
	err := hs.s.Shutdown(context.Background())
	if err != nil && err != http.ErrServerClosed {
		// 这里发生了错误，外层处理这个错误时也要关闭文件存储系统
		return err
	}
	atomic.StoreInt32(&hs.closed, 0)

	// 再关闭文件存储系统
	if storage != nil {
		err := storage.CloseFS()
		if err != nil {
			return fmt.Errorf("failed to shutdown the storage engine: %w", err)
		}
	}

	return nil
}
