package vfs

import (
	"errors"
	"fmt"
	"time"

	"github.com/auula/wiredkv/types"
)

type Kind int8

const (
	Set Kind = iota
	ZSet
	List
	Text
	Tables
	Binary
	Number
	Unknown
)

// | DEL 1 | KIND 1 | EAT 8 | CAT 8 | KLEN 8 | VLEN 8 | KEY ? | VALUE ? | CRC32 4 |
type Segment struct {
	Tombstone int8
	Type      Kind
	ExpiredAt uint64
	CreatedAt uint64
	KeySize   uint32
	ValueSize uint32
	data      []byte
}

type Serializable interface {
	ToBytes() []byte
}

// NewSegment 使用数据类型初始化并返回对应的 Segment
func NewSegment(data Serializable) (*Segment, error) {
	kind, err := toKind(data)
	if err != nil {
		return nil, fmt.Errorf("unsupported data type: %w", err)
	}

	// 如果类型不匹配，则返回错误
	return &Segment{
		Type: kind,
		data: data.ToBytes(),
	}, nil
}

func (s *Segment) Kind() Kind {
	return s.Type
}

func (s *Segment) Size() int {
	return len(s.data)
}

func (s *Segment) ToLittleEndian() []byte {
	// 这里直接初始化为小端磁盘存储格式
	// 日志记录到附加信息序列化
	// 上层的 lfs 只需要写入对于的记录到文件中就可以
	return []byte{}
}

func (s *Segment) ToSet() *types.Set {
	if s.Type != Set {
		return nil
	}
	// 假设您的数据是 JSON 或某种结构体，可以进行反序列化
	var set types.Set
	// Deserialize s.data to set (具体根据类型定义来做反序列化)
	return &set
}

func (s *Segment) ToZSet() *types.ZSet {
	return nil
}

func (s *Segment) ToText() *types.Text {
	return nil
}

func (s *Segment) ToList() *types.List {
	return nil
}

func (s *Segment) ToTables() *types.Tables {
	return nil
}

func (s *Segment) ToBinary() *types.Binary {
	return nil
}

func (s *Segment) ToNumber() *types.Number {
	return nil
}

func (s *Segment) TTL() int64 {
	now := uint64(time.Now().Unix())
	if s.ExpiredAt > 0 && s.ExpiredAt > now {
		return int64(s.ExpiredAt - now)
	}
	return -1
}

// 将类型映射为 Kind 的辅助函数
func toKind(data Serializable) (Kind, error) {
	switch data.(type) {
	case *types.Set:
		return Set, nil
	case *types.ZSet:
		return ZSet, nil
	case *types.List:
		return List, nil
	case *types.Text:
		return Text, nil
	case *types.Tables:
		return Tables, nil
	case *types.Binary:
		return Binary, nil
	case *types.Number:
		return Number, nil
	default:
		return Unknown, errors.New("unknown data type")
	}
}
