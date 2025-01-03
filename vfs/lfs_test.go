package vfs

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"testing"
)

// TestSerializedIndex 测试 serializedIndex 函数
func TestSerializedIndex(t *testing.T) {
	// 创建一个测试的 INode
	inode := &INode{
		RegionID:  1234,
		Position:  5678,
		Length:    100,
		ExpiredAt: 1617181723,
		CreatedAt: 1617181623,
	}

	// 计算预期的字节切片
	expectedLength := 48

	// 调用 serializeIndex
	result, err := serializedIndex(1001, inode)
	if err != nil {
		t.Fatalf("serialized index failed: %v", err)
	}

	// 检查返回的字节切片长度
	if len(result) != expectedLength {
		t.Errorf("expected result length %d, got %d", expectedLength, len(result))
	}

	// 验证内容字段进行反序列化并检查
	inum, node, err := deserializedIndex(result)

	if err != nil {
		t.Errorf("failed to deserialized: %v", err)
	}

	// 验证字段是否一致
	if inum != 1001 {
		t.Errorf("expected inum %d, got %d", 1001, inum)
	}
	if node.RegionID != inode.RegionID {
		t.Errorf("expected RegionID %d, got %d", inode.RegionID, node.RegionID)
	}
	if node.Position != inode.Position {
		t.Errorf("expected Offset %d, got %d", inode.Position, node.RegionID)
	}
	if node.Length != inode.Length {
		t.Errorf("expected Length %d, got %d", inode.Length, node.Length)
	}
	if node.ExpiredAt != inode.ExpiredAt {
		t.Errorf("expected ExpiredAt %d, got %d", inode.ExpiredAt, node.ExpiredAt)
	}
	if node.CreatedAt != inode.CreatedAt {
		t.Errorf("expected CreatedAt %d, got %d", inode.CreatedAt, node.CreatedAt)
	}

}

// 测试 parseSegment
func TestParseSegment(t *testing.T) {
	// 创建临时文件
	tmpFile, err := os.CreateTemp("", "segment_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name()) // 确保测试结束时删除临时文件

	// 准备测试数据
	tombstone := int8(1)
	segType := Kind(2)
	expiredAt := uint64(1688991234)
	createdAt := uint64(1688999999)
	key := "example-key"
	keySize := uint32(len(key))
	value := "example-value"
	valueSize := uint32(len(value))

	// 写入段数据
	buf := make([]byte, 26+len(key)+len(value)) // 固定部分 26 字节 + key 和 value 的长度
	writeOffset := 0

	// Tombstone (1 字节)
	buf[writeOffset] = byte(tombstone)
	writeOffset += 1

	// Type (1 字节)
	buf[writeOffset] = byte(segType)
	writeOffset += 1

	// ExpiredAt (8 字节)
	binary.LittleEndian.PutUint64(buf[writeOffset:writeOffset+8], expiredAt)
	writeOffset += 8

	// CreatedAt (8 字节)
	binary.LittleEndian.PutUint64(buf[writeOffset:writeOffset+8], createdAt)
	writeOffset += 8

	// KeySize (4 字节)
	binary.LittleEndian.PutUint32(buf[writeOffset:writeOffset+4], keySize)
	writeOffset += 4

	// ValueSize (4 字节)
	binary.LittleEndian.PutUint32(buf[writeOffset:writeOffset+4], valueSize)
	writeOffset += 4

	// Key
	copy(buf[writeOffset:writeOffset+len(key)], key)
	writeOffset += len(key)

	// Value
	copy(buf[writeOffset:writeOffset+len(value)], value)
	writeOffset += len(value)

	// 计算这条记录的 checksum
	checksum := crc32.ChecksumIEEE(buf)

	// 把计算的 checksum 添加进去
	checksumBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(checksumBytes, checksum)
	buf = append(buf, checksumBytes...)

	// 启用数据加密器转换数据
	trans := NewTransformer()
	// 写入文件内容
	if _, err := trans.Write(tmpFile, buf); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}

	// 测试 parseSegment 函数
	offset := uint64(0)

	// 仅解析固定部分，一条 segment 格式如下：
	// | DEL 1 | KIND 1 | EAT 8 | CAT 8 | KLEN 4 | VLEN 4 | KEY ? | VALUE ? | CRC32 4 |
	inum, seg, err := readSegment(tmpFile, offset, 26)

	if err != nil {
		t.Fatalf("failed to parse segment: %v", err)
	}

	t.Logf("inum = %v , seg = %v", inum, seg)

	// 验证解析结果
	expectedInum := HashSum64(key)
	if inum != expectedInum {
		t.Errorf("unexpected inum: got %d, want %d", inum, expectedInum)
	}

	if seg.Tombstone != tombstone {
		t.Errorf("unexpected tombstone: got %d, want %d", seg.Tombstone, tombstone)
	}

	if seg.Type != segType {
		t.Errorf("unexpected type: got %d, want %d", seg.Type, segType)
	}

	if seg.ExpiredAt != expiredAt {
		t.Errorf("unexpected expiredAt: got %d, want %d", seg.ExpiredAt, expiredAt)
	}

	if seg.CreatedAt != createdAt {
		t.Errorf("unexpected createdAt: got %d, want %d", seg.CreatedAt, createdAt)
	}

	if seg.KeySize != keySize {
		t.Errorf("unexpected keySize: got %d, want %d", seg.KeySize, keySize)
	}

	t.Logf("%v", string(seg.data))
}
