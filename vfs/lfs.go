package vfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/auula/wiredkv/utils"
)

const RWCA = os.O_RDWR | os.O_CREATE | os.O_APPEND

const (
	_  = 1 << (10 * iota) // skip iota = 0
	KB                    // 2^10 = 1024
	MB                    // 2^20 = 1048576
	GB                    // 2^30 = 1073741824
)

var (
	once             sync.Once
	indexShard       = 5
	instance         *LogStructuredFS
	fsPerm           = fs.FileMode(0755)
	fileExtension    = ".wdb"
	indexFileName    = "index.wdb"
	regionThreshold  = int64(1 * GB) // 1GB
	dataFileMetadata = []byte{0xDB, 0x0, 0x0, 0x1}
)

type Options struct {
	Path      string
	FsPerm    os.FileMode
	Threshold uint8 // 这个的大小会影响到垃圾回收执行的时间
}

// INode represents a file system node with metadata.
type INode struct {
	RegionID  uint64 // Unique identifier for the region
	Position  uint64 // Position within the file
	Length    uint32 // Data record length
	ExpiredAt uint64 // Expiration time of the INode (UNIX timestamp in seconds)
	CreatedAt uint64 // Creation time of the INode (UNIX timestamp in seconds)
}

type indexMap struct {
	mu    sync.RWMutex      // 每个分片使用独立的锁
	index map[uint64]*INode // 存储映射
}

// LogStructuredFS represents the virtual file storage system.
type LogStructuredFS struct {
	mu        sync.Mutex
	offset    uint64
	regionID  uint64
	directory string
	indexs    []*indexMap         // Index mapping for INode references
	active    *os.File            // Currently active file for writing
	regions   map[uint64]*os.File // Archived files keyed by unique file ID
}

// 根据某种哈希函数（如简单的模运算）来选择分片
func (lfs *LogStructuredFS) getShardIndex(inum uint64) *indexMap {
	lfs.mu.Unlock()
	defer lfs.mu.Unlock()
	return lfs.indexs[inum%uint64(indexShard)]
}

// 使用 `getShardIndex` 获取分片，并加锁进行操作
func (lfs *LogStructuredFS) AddSegment(inum uint64, seg Segment, ttl uint64) {
	shard := lfs.getShardIndex(inum)
	inode := &INode{
		RegionID: lfs.regionID,
		Position: lfs.offset,
		// Length 是通过 segment 计算出来的
		Length:    0,
		CreatedAt: uint64(time.Now().Unix()),
		ExpiredAt: 0,
	}

	if ttl > 0 {
		inode.ExpiredAt = uint64(time.Now().Add(time.Second * time.Duration(ttl)).Unix())
	}

	shard.mu.Lock()
	shard.index[inum] = inode
	shard.mu.Unlock()

}

func (lfs *LogStructuredFS) GetINode(inum uint64) (*INode, bool) {
	shard := lfs.getShardIndex(inum)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	inode, exists := shard.index[inum]
	return inode, exists
}

func (lfs *LogStructuredFS) BatchINodes(inodes ...*INode) {

}

func HashSum64(key string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(key))
	return h.Sum64()
}

func (lfs *LogStructuredFS) ChangeRegions() error {
	lfs.mu.Lock()
	defer lfs.mu.Unlock()

	err := utils.CloseFile(lfs.active)
	if err != nil {
		return fmt.Errorf("failed to close active file: %w", err)
	}

	file, err := os.Open(filepath.Join(lfs.directory, formatDataFileName(lfs.regionID)))
	if err != nil {
		return fmt.Errorf("failed to change active file read only: %w", err)
	}
	lfs.regions[lfs.regionID] = file

	err = lfs.createActiveRegion()
	if err != nil {
		return fmt.Errorf("failed to chanage active file: %w", err)
	}

	return nil
}

func (lfs *LogStructuredFS) createActiveRegion() error {
	lfs.mu.Lock()
	defer lfs.mu.Unlock()
	lfs.regionID += 1
	fileName, err := generateFileName(lfs.regionID)
	if err != nil {
		return fmt.Errorf("failed to new data file name: %w", err)
	}

	active, err := os.OpenFile(filepath.Join(lfs.directory, fileName), RWCA, fsPerm)
	if err != nil {
		return fmt.Errorf("failed to create active file: %w", err)
	}

	n, err := active.Write(dataFileMetadata)
	if err != nil {
		return fmt.Errorf("failed to write data file metadata: %w", err)
	}

	if n != len(dataFileMetadata) {
		return errors.New("failed to new file metadata write")
	}

	lfs.active = active
	lfs.offset = uint64(len(dataFileMetadata))

	return nil
}

func (lfs *LogStructuredFS) recoverRegions() error {
	lfs.mu.Lock()
	defer lfs.mu.Unlock()
	files, err := os.ReadDir(lfs.directory)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	if len(files) <= 0 {
		// 它这个错误设计和 JVM 异常相比很垃圾
		err := lfs.createActiveRegion()
		if err != nil {
			return err
		}
		// 可以直接这么写，但是会丢弃错误处理上下文
		// return lfs.createActiveRegion()
		return nil
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), fileExtension) {
			regions, err := os.Open(filepath.Join(lfs.directory, file.Name()))
			if err != nil {
				return fmt.Errorf("failed to open data file: %w", err)
			}

			regionID, err := parseDataFileName(file.Name())
			if err != nil {
				return fmt.Errorf("failed to get regions id: %w", err)
			}
			lfs.regions[regionID] = regions
		}
	}

	var regionIds []uint64
	for v := range lfs.regions {
		regionIds = append(regionIds, v)
	}
	// 对 regionIds 切片从小到大排序
	sort.Slice(regionIds, func(i, j int) bool {
		return regionIds[i] < regionIds[j]
	})
	// 找到最新数据文件的版本
	lfs.regionID = regionIds[len(regionIds)-1]

	// 如果最大那个 region 文件没有达到阀值就不用创建新文件，如果大于就创建新的文件
	activeRegion, ok := lfs.regions[lfs.regionID]
	if !ok {
		return fmt.Errorf("region file not found for region id: %d", lfs.regionID)
	}
	stat, err := activeRegion.Stat()
	if err != nil {
		return fmt.Errorf("failed to get region file info: %w", err)
	}

	if stat.Size() >= regionThreshold {
		return lfs.createActiveRegion()
	} else {
		offset, err := activeRegion.Seek(0, io.SeekEnd)
		if err != nil {
			return fmt.Errorf("failed to get region file offset: %w", err)
		}
		lfs.active = activeRegion
		lfs.offset = uint64(offset)
	}

	return nil
}

// recoveryIndex 会对磁盘上的数据文件执行恢复索引操作，步骤如下：
// 读取索引文件快照文件，从快照文件里面恢复索引
// 不同于 bitcask 对 hint 文件是在 compressor 过程中生成
// bitcask 中 hint 文件是在压缩过程中生成 hint 快照
// 并不能代表全部即时内存索引状态
// vasedb 则完全设计了不同的方案，如果是 close 正常关闭的就会生成 index 文件
// 如果数据文件有 index 文件则直接从 index 文件中恢复
// 没有就在启动的全局扫描数据文件重新构建索引文件
func (lfs *LogStructuredFS) recoveryIndex() error {
	lfs.mu.Lock()
	defer lfs.mu.Unlock()
	// 构造完整的文件路径
	filePath := filepath.Join(lfs.directory, indexFileName)
	if utils.IsExist(filePath) {
		// 如果存在索引文件就恢复
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open index file: %w", err)
		}
		defer file.Close()

		err = recoveryIndex(file, lfs.indexs)
		if err != nil {
			return fmt.Errorf("failed to recovery index mapping: %w", err)
		}

		return nil
	}

	// 如果不存在索引文件就从 regions 文件全局扫描恢复
	// 如果数据文件非常大，而且文件非常多，恢复多时间就越长
	// 如果垃圾回收越频繁，你数据文件就变小，启动时间就越快
	// 但是如果垃圾回收越频繁，可能会影响到整体数据读取写性能
	err := crashRecoveryAllIndex(lfs.regions, lfs.indexs)
	if err != nil {
		return fmt.Errorf("failed to crash recovery index: %w", err)
	}

	return nil
}

func OpenFS(opt *Options) (*LogStructuredFS, error) {
	var top_err error
	once.Do(func() {
		if instance != nil {
			return
		}

		// single region max size = 255GB
		regionThreshold = int64(opt.Threshold) * GB

		err := checkFileSystem(opt.Path)
		if err != nil {
			top_err = err
			return
		}

		fsPerm = opt.FsPerm
		instance = &LogStructuredFS{
			indexs:    make([]*indexMap, indexShard),
			regions:   make(map[uint64]*os.File, 10),
			offset:    uint64(len(dataFileMetadata)),
			regionID:  0,
			directory: opt.Path,
		}

		for i := 0; i < indexShard; i++ {
			instance.indexs[i] = &indexMap{
				mu:    sync.RWMutex{},
				index: make(map[uint64]*INode, 100000),
			}
		}

		// 先对已有的数据文件执行恢复操作，并且初始化内存中的数据版本号
		err = instance.recoverRegions()
		if err != nil {
			top_err = fmt.Errorf("failed to recover data regions: %w", err)
			return
		}

		err = instance.recoveryIndex()
		if err != nil {
			top_err = fmt.Errorf("failed to recover regions index: %w", err)
			return
		}

	})

	if top_err != nil {
		return nil, fmt.Errorf("failed to open file system: %w", top_err)
	}

	// 单例子模式，但是挡不住其他包通过 new(LogStructuredFS) 也能创建一个实例，那这样根本不起作用了
	return instance, nil
}

func (lfs *LogStructuredFS) CloseFS() error {
	lfs.mu.Lock()
	defer lfs.mu.Unlock()
	for _, file := range lfs.regions {
		err := utils.CloseFile(file)
		if err != nil {
			return fmt.Errorf("failed to close region file: %w", err)
		}
	}

	err := utils.CloseFile(lfs.active)
	if err != nil {
		return fmt.Errorf("failed to close active region: %w", err)
	}

	// 如果有 index 文件的快照，就从 index 文件快照进行恢复，如果没有就全局扫描
	return lfs.ExportSnapshotIndex()
}

// ExportSnapshotIndex 是正常程序退出是所做的操作，导出内存索引快照到磁盘文件
// 当前的设计方案对于内存资源较少的系统有限制，
// 例如 RAM 512 MB < 1GB，如果 1GB 快照不能全部序列化到磁盘上，
// 映射大文件到内存可能不是一个好的选择，因为它会占用大量的虚拟内存空间，会出现 swap 交换内存页。
func (lfs *LogStructuredFS) ExportSnapshotIndex() error {
	lfs.mu.Lock()
	defer lfs.mu.Unlock()

	// 使用局部 Transformer 实例
	trans := NewTransformer()

	filePath := filepath.Join(lfs.directory, indexFileName)
	fd, err := os.OpenFile(filePath, RWCA, fsPerm)
	if err != nil {
		return fmt.Errorf("failed to generate index snapshot file: %w", err)
	}
	defer utils.CloseFile(fd)

	// 写入元数据
	n, err := fd.Write(dataFileMetadata)
	if err != nil {
		return fmt.Errorf("failed to write index file metadata: %w", err)
	}

	if n != len(dataFileMetadata) {
		return errors.New("index file metadata write incomplete")
	}

	// 遍历分片索引并写入
	for _, indexs := range lfs.indexs {
		indexs.mu.RLock()
		defer indexs.mu.RUnlock()
		for inum, inode := range indexs.index {
			bytes, err := serializedIndex(inum, inode)
			if err != nil {
				return fmt.Errorf("failed to serialized index (inum: %d): %w", inum, err)
			}
			_, err = trans.Write(fd, bytes)
			if err != nil {
				return fmt.Errorf("failed to write serialized index (inum: %d): %w", inum, err)
			}
		}
	}

	return nil
}

func recoveryIndex(fd *os.File, indexs []*indexMap) error {
	// 在恢复操作的时候不需要上锁
	offset := int64(len(dataFileMetadata))
	trans := NewTransformer()

	finfo, err := fd.Stat()
	if err != nil {
		return err
	}

	type index struct {
		inum  uint64
		inode *INode
	}

	// 共享并行处理的数据
	nqueue := make(chan index, (finfo.Size()-offset)/48)
	// 定义一个错误通道，用于捕获 goroutine 中的错误
	// 只捕获到第一个错误，一旦有错误全局停止直接返回
	equeue := make(chan error, 1)

	// 定义一个 WaitGroup 来等待所有 goroutine 完成
	var wg sync.WaitGroup

	// 生产者 goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(nqueue)

		for offset < finfo.Size() && len(equeue) == 0 {
			bytes, err := trans.ReadAt(fd, offset, 48)
			if err != nil {
				equeue <- fmt.Errorf("failed to read index node: %w", err)
				return
			}

			offset += 48

			inum, inode, err := deserializedIndex(bytes)
			if err != nil {
				equeue <- fmt.Errorf("failed to deserialize index (inum: %d): %w", inum, err)
				return
			}

			nqueue <- index{inum: inum, inode: inode}
		}
	}()

	// 消费者 goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for node := range nqueue {
			imap := indexs[node.inum%uint64(indexShard)]
			if imap != nil {
				imap.index[node.inum] = node.inode
			} else {
				// 这里对应着 for 循环的 len(equeue) == 0 条件
				// 防止消费者 goroutine 发生了错误已经停止了
				// 但是生产者 goroutine 还在读取反序列化索引
				// 导致不能立即执行 defer wg.Done() 做无意义的工作
				// 目的是为尽快恢复阻塞的 wg.Wait() 执行主 goroutine 返回
				equeue <- errors.New("no corresponding index shard")
				return
			}
		}
	}()

	// 等待所有 goroutine 完成
	wg.Wait()

	// 判断错误通道是否有值，捕获错误
	select {
	case err := <-equeue:
		close(equeue)
		return err
	default:
		close(equeue)
		return nil
	}
}

// crashRecoveryAllIndex 会对 regions 文件集合进行解析恢复内存索引，步骤如下：
// 1. 崩溃恢复逻辑，扫描所有的数据文件
// 2. 读取每条数据记录的前 26 字节 MetaInfo
// 3. 对这些记录进行重放，并且查看 DEL 值是否为 1
// 4. 如果是 1 则对内存的索引进行删除
// 5. 否则直接将磁盘元数据重构建为索引
// | DEL 1 | KIND 1 | EAT 8 | CAT 8 | KLEN 4 | VLEN 4 | KEY ? | VALUE ? | CRC32 4 |
func crashRecoveryAllIndex(regions map[uint64]*os.File, indexs []*indexMap) error {
	var regionIds []uint64
	for v := range regions {
		regionIds = append(regionIds, v)
	}

	// 对 regionIds 切片从小到大排序
	sort.Slice(regionIds, func(i, j int) bool {
		return regionIds[i] < regionIds[j]
	})

	// 3. 遍历每个数据文件（region）
	for _, regionId := range regionIds {
		fd, ok := regions[uint64(regionId)]
		if !ok {
			return fmt.Errorf("data file does not exist regions id: %d", regionId)
		}

		finfo, err := fd.Stat()
		if err != nil {
			return err
		}

		offset := uint64(len(dataFileMetadata))

		for offset < uint64(finfo.Size()) {
			inum, segment, err := readSegment(fd, offset, 26)
			if err != nil {
				return fmt.Errorf("failed to parse data file segment: %w", err)
			}

			imap := indexs[inum%uint64(indexShard)]
			if imap != nil {
				// 如果是一条删除操作的记录，就将该记录对应索引删除
				if segment.Tombstone == 1 {
					delete(imap.index, inum)
					continue
				}

				// 计算一整块记录的大小，+4 CRC 校验码占用 4 个字节
				size := 26 + segment.KeySize + segment.ValueSize + 4

				// 否则继续往下执行，构建重新 inode 索引
				imap.index[inum] = &INode{
					RegionID:  regionId,
					Position:  offset,
					Length:    size,
					CreatedAt: segment.CreatedAt,
					ExpiredAt: segment.ExpiredAt,
				}

				offset += uint64(size)
			} else {
				// 找不到索引就抛出异常
				return errors.New("no corresponding index shard")
			}
		}

	}

	return nil
}

func validateFileHeader(file *os.File) error {
	var fileHeader [4]byte
	n, err := file.Read(fileHeader[:])
	if err != nil {
		return err
	}

	if n != len(dataFileMetadata) {
		return errors.New("file is too short to contain valid signature")
	}

	if !bytes.Equal(fileHeader[:], dataFileMetadata[:]) {
		return fmt.Errorf("unsupported data file version: %v", file.Name())
	}

	return nil
}

func checkFileSystem(path string) error {
	if !utils.IsExist(path) {
		err := os.MkdirAll(path, fsPerm)
		if err != nil {
			return err
		}
	}

	files, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	if len(files) > 0 {
		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(file.Name(), fileExtension) {
				if len(file.Name()) == 8 && strings.HasPrefix(file.Name(), "0") {
					file, err := os.Open(filepath.Join(path, file.Name()))
					if err != nil {
						return fmt.Errorf("failed to check data file: %w", err)
					}
					defer utils.CloseFile(file)

					err = validateFileHeader(file)
					if err != nil {
						return fmt.Errorf("failed to validated data file header: %w", err)
					}
				}
			}

			if !file.IsDir() && file.Name() == indexFileName {
				file, err := os.Open(filepath.Join(path, file.Name()))
				if err != nil {
					return fmt.Errorf("failed to check index file: %w", err)
				}
				defer utils.CloseFile(file)

				err = validateFileHeader(file)
				if err != nil {
					return fmt.Errorf("failed to validated index file header: %w", err)
				}
			}
		}
	}

	return nil
}

// | DEL 1 | KIND 1 | EAT 8 | CAT 8 | KLEN 4 | VLEN 4 | KEY ? | VALUE ? | CRC32 4 |
func readSegment(fd *os.File, offset uint64, bufsize int64) (uint64, *Segment, error) {
	// 数据转换器
	trans := NewTransformer()
	// 从指定的 offset 读取数据
	buf, err := trans.ReadAt(fd, int64(offset), bufsize)
	if err != nil {
		return 0, nil, err
	}

	// 初始化 Segment 结构
	var seg Segment
	readOffset := 0

	// 1. 解析 Tombstone (1 字节)
	seg.Tombstone = int8(buf[readOffset])
	readOffset += 1

	// 2. 解析 Type (1 字节)
	seg.Type = Kind(buf[readOffset])
	readOffset += 1

	// 3. 解析 ExpiredAt (8 字节，小端格式)
	seg.ExpiredAt = binary.LittleEndian.Uint64(buf[readOffset : readOffset+8])
	readOffset += 8

	// 4. 解析 CreatedAt (8 字节，小端格式)
	seg.CreatedAt = binary.LittleEndian.Uint64(buf[readOffset : readOffset+8])
	readOffset += 8

	// 5. 解析 KeySize (4 字节，小端格式)
	seg.KeySize = binary.LittleEndian.Uint32(buf[readOffset : readOffset+4])
	readOffset += 4

	// 7. 解析 ValueSize (4 字节，小端格式)
	seg.ValueSize = binary.LittleEndian.Uint32(buf[readOffset : readOffset+4])
	readOffset += 4

	// 8. 原始 buf 不够用存储 key 的值，从指定的 offset 读取 key 实际的数据
	keybuf, err := trans.ReadAt(fd, int64(offset)+int64(readOffset), int64(seg.KeySize))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse key in segment: %w", err)
	}

	readOffset += int(seg.KeySize)

	// 10. 原始 buf 不够用存储 value 的值，从指定的 offset 读取 value 实际的数据
	valuebuf, err := trans.ReadAt(fd, int64(offset)+int64(readOffset), int64(seg.ValueSize))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse value in segment: %w", err)
	}

	readOffset += int(seg.ValueSize)

	// 12. 读取 checksum (4 字节)
	checksumBuf, err := trans.ReadAt(fd, int64(offset)+int64(readOffset), 4)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read checksum in segment: %w", err)
	}

	// 将 checksum 从字节数组转换为 uint32
	checksum := binary.LittleEndian.Uint32(checksumBuf)

	// 13. 将 key 和 value 数据拼接后计算 CRC32 校验和
	buf = append(buf, keybuf...)
	buf = append(buf, valuebuf...)

	// 14. 校验 checksum 是否一致
	if checksum != crc32.ChecksumIEEE(buf) {
		return 0, nil, fmt.Errorf("failed to crc32 checksum mismatch: %d", checksum)
	}

	// 15. 更新 Segment 数据字段为读取的 valuebuf
	seg.data = valuebuf

	// 16. 返回 inum 和 解析后的 Segment 以及 nil 错误
	return HashSum64(string(keybuf)), &seg, nil
}

func generateFileName(regionID uint64) (string, error) {
	fileName := fmt.Sprintf("%08d%s", regionID, fileExtension)
	if len(fileName) == 8 && strings.HasPrefix(fileName, "0") {
		return fileName, nil
	}
	return "", fmt.Errorf("new region id %d cannot be converted to a valid file name", regionID)
}

// parseDataFileName 将文件名（如 0000001.vsdb）中的数字部分转换为 uint64
func parseDataFileName(fileName string) (uint64, error) {
	parts := strings.Split(fileName, ".")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid file name format: %s", fileName)
	}

	// 转换为 uint16
	number, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse number from file name: %w", err)
	}

	return uint64(number), nil
}

// formatDataFileName 将 uint16 转换为文件名格式（如 1 转为 0000001.vsdb）
func formatDataFileName(number uint64) string {
	return fmt.Sprintf("%08d%s", number, fileExtension)
}

// serializedIndex 将索引进行序列化为可以恢复的文件快照记录格式：
// | INUM 8 | RID 8  | POS 8 | LEN 4 | EAT 8 | CAT 8 | CRC32 4 |
func serializedIndex(inum uint64, inode *INode) ([]byte, error) {
	// 创建一个字节缓冲区
	buf := new(bytes.Buffer)

	// 按顺序写入各个字段
	binary.Write(buf, binary.LittleEndian, inum)
	binary.Write(buf, binary.LittleEndian, inode.RegionID)
	binary.Write(buf, binary.LittleEndian, inode.Position)
	binary.Write(buf, binary.LittleEndian, inode.Length)
	binary.Write(buf, binary.LittleEndian, inode.ExpiredAt)
	binary.Write(buf, binary.LittleEndian, inode.CreatedAt)

	// 计算 CRC32 校验码
	checksum := crc32.ChecksumIEEE(buf.Bytes())

	// 将 CRC32 校验码写入字节缓冲区（4 字节）
	binary.Write(buf, binary.LittleEndian, checksum)

	// 返回包含 CRC32 校验码的字节切片
	return buf.Bytes(), nil
}

// deserializedIndex 将索引文件快照恢复为内存结构体：
// | INUM 8 | RID 8  | OFS 8 | LEN 4 | EAT 8 | CAT 8 | CRC32 4 |
func deserializedIndex(data []byte) (uint64, *INode, error) {
	buf := bytes.NewReader(data)
	// 反序列化 inum
	var inum uint64
	err := binary.Read(buf, binary.LittleEndian, &inum)
	if err != nil {
		return 0, nil, err
	}

	// 反序列化 INode 的各个字段
	var inode INode
	err = binary.Read(buf, binary.LittleEndian, &inode.RegionID)
	if err != nil {
		return 0, nil, err
	}

	err = binary.Read(buf, binary.LittleEndian, &inode.Position)
	if err != nil {
		return 0, nil, err
	}

	err = binary.Read(buf, binary.LittleEndian, &inode.Length)
	if err != nil {
		return 0, nil, err
	}

	err = binary.Read(buf, binary.LittleEndian, &inode.ExpiredAt)
	if err != nil {
		return 0, nil, err
	}

	err = binary.Read(buf, binary.LittleEndian, &inode.CreatedAt)
	if err != nil {
		return 0, nil, err
	}

	// 反序列化 CRC32 校验码并验证
	var checksum uint32
	err = binary.Read(buf, binary.LittleEndian, &checksum)
	if err != nil {
		return 0, nil, err
	}

	// 计算数据的 CRC32 校验码，如果校验码不一致，返回错误
	if checksum != crc32.ChecksumIEEE(data[:len(data)-4]) {
		return 0, nil, fmt.Errorf("failed to crc32 checksum mismatch: %d", checksum)
	}

	return inum, &inode, nil
}
