package vfs

import (
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	// 使用整数位标志存储状态
	EnabledEncryption  = 1 << iota // 1: 0001
	EnabledCompression             // 2: 0010
)

type Compressor interface {
	Compress(data []byte) ([]byte, error)
	Decompress(data []byte) ([]byte, error)
}

type Encryptor interface {
	Encode(secret, data []byte) ([]byte, error)
	Decode(secret, data []byte) ([]byte, error)
}

type Transformer struct {
	Encryptor
	Compressor
	flags  int
	secret []byte
}

func NewTransformer() *Transformer {
	return &Transformer{
		flags:      0,
		Encryptor:  nil,
		Compressor: nil,
	}
}

func (t *Transformer) EnableEncryption() {
	t.flags |= EnabledEncryption
}

func (t *Transformer) EnableCompression() {
	t.flags |= EnabledCompression
}

func (t *Transformer) DisableEncryption() {
	t.flags &^= EnabledEncryption
}

func (t *Transformer) DisableCompression() {
	t.flags &^= EnabledCompression
}

func (t *Transformer) IsEncryptionEnabled() bool {
	return t.flags&EnabledEncryption != 0
}

func (t *Transformer) IsCompressionEnabled() bool {
	return t.flags&EnabledCompression != 0
}

func (t *Transformer) DisableAll() {
	t.flags = 0
}

func (t *Transformer) SetEncryptor(encryptor Encryptor, secret []byte) error {
	if len(secret) < 16 {
		return errors.New("secret char length too short")
	}
	t.secret = secret
	t.Encryptor = encryptor
	t.EnableEncryption()
	return nil
}

func (t *Transformer) SetCompressor(compressor Compressor) {
	t.Compressor = compressor
	t.EnableCompression()
}

// fd 必须实现 io.ReadWriteCloser 接口
func (t *Transformer) Write(fd io.ReadWriteCloser, data []byte) (int, error) {
	// 压缩数据
	if t.IsCompressionEnabled() && t.Compressor != nil {
		var err error
		data, err = t.Compress(data)
		if err != nil {
			return 0, fmt.Errorf("failed to compress data: %w", err)
		}
	}

	// 加密数据
	if t.IsEncryptionEnabled() && t.Encryptor != nil {
		var err error
		data, err = t.Encode(t.secret, data)
		if err != nil {
			return 0, fmt.Errorf("failed to encrypt data: %w", err)
		}
	}

	// 写入数据到 fd
	n, err := fd.Write(data)
	if err != nil {
		return 0, fmt.Errorf("failed to write data: %w", err)
	}
	return n, nil
}

// fd 必须实现 io.ReadWriteCloser 接口
func (t *Transformer) Read(fd io.ReadWriteCloser, bufsize int64) ([]byte, error) {
	buf := make([]byte, bufsize)
	_, err := fd.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read io device: %w", err)
	}

	// 解密数据
	if t.IsEncryptionEnabled() && t.Encryptor != nil {
		buf, err = t.Decode(t.secret, buf)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}
	}

	// 解压缩数据
	if t.IsCompressionEnabled() && t.Compressor != nil {
		buf, err = t.Decompress(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress data: %w", err)
		}
	}

	return buf, nil
}

func (t *Transformer) ReadAt(fd *os.File, offset, bufsize int64) ([]byte, error) {
	// 创建缓冲区
	buf := make([]byte, bufsize)

	// 从文件指定偏移读取数据
	_, err := fd.ReadAt(buf, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// 如果启用了压缩功能，则先解压
	if t.IsCompressionEnabled() && t.Compressor != nil {
		buf, err = t.Decompress(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress data: %w", err)
		}
	}

	// 如果启用了加密功能，则解密
	if t.IsEncryptionEnabled() && t.Encryptor != nil {
		buf, err = t.Decode(t.secret, buf)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}
	}

	// 返回最终的数据
	return buf, nil
}
