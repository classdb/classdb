package conf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

const (
	extension       = "yaml"
	fileName        = "config"
	defaultFilePath = ""
	// 设置默认文件系统权限
	FsPerm = fs.FileMode(0755)
	// DefaultConfigJSON configure json string
	DefaultConfigJSON = `
	{
		"port": 2468,
		"path": "/tmp/wiredkv",
		"debug": false,
		"logpath": "/tmp/wiredkv/out.log",
		"auth": "Are we wide open to the world?",
		"region": {
			"enable": true,
			"second": 18000,
			"threshold": 3
		},
		"encryptor": {
			"enable": false,
			"secret": "your-static-data-secret"
		},
		"compressor": {
			"enable": false
		},
		"allow_ip": null
	}
`
)

var (
	// Settings global configure options
	Settings *ServerOptions = new(ServerOptions)
	// Default is the default configuration
	Default *ServerOptions = new(ServerOptions)
)

func init() {
	// 先读内置默认配置，设置为全局的配置
	_ = Default.Unmarshal([]byte(DefaultConfigJSON))
	// 当初始化完成之后应该使用此 Settings 配置
	_ = Settings.Unmarshal([]byte(DefaultConfigJSON))
}

// HasCustom checked enable custom config
func HasCustom(path string) bool {
	return path != defaultFilePath
}

type Validator interface {
	Validate(*ServerOptions) error
}

type PortValidator struct{}

func (PortValidator) Validate(opt *ServerOptions) error {
	return validatePort(opt.Port)
}

type PathValidator struct{}

func (PathValidator) Validate(opt *ServerOptions) error {
	return validatePath(opt.Path)
}

type AuthValidator struct{}

func (AuthValidator) Validate(opt *ServerOptions) error {
	return validatePassword(opt.Path)
}

func validatePort(port int) error {
	if port <= 1024 || port >= 65535 {
		return errors.New("port range must be between 1025 and 65534")
	}
	return nil
}

func validatePath(path string) error {
	if path == "" {
		return errors.New("data directory path cannot be empty")
	}
	return nil
}

func validatePassword(password string) error {
	if password == "" {
		return errors.New("auth password cannot be empty")
	}
	return nil
}

func Vaildated(opt *ServerOptions) error {
	validators := []Validator{
		PortValidator{},
		PathValidator{},
		AuthValidator{},
	}

	for _, validator := range validators {
		err := validator.Validate(opt)
		if err != nil {
			return fmt.Errorf("failed to validator server configure: %w", err)
		}
	}

	return nil
}

// Load through a configuration file
func Load(file string, opt *ServerOptions) error {
	_, err := os.Stat(file)
	if err != nil {
		return err
	}

	v := viper.New()
	v.SetConfigType(extension)
	v.SetConfigFile(file)

	err = v.ReadInConfig()
	if err != nil {
		return err
	}

	return v.Unmarshal(opt)
}

func saved(path string, opt *ServerOptions) error {
	yamlData, _ := yaml.Marshal(&opt)
	return os.WriteFile(path, yamlData, FsPerm)
}

func (opt *ServerOptions) SavedAs(path string) error {
	return saved(path, opt)
}

func (opt *ServerOptions) Saved() error {
	return saved(filepath.Join(opt.Path, fileName+"."+extension), opt)
}

func (opt *ServerOptions) Unmarshal(data []byte) error {
	return json.Unmarshal(data, &opt)
}

func (opt *ServerOptions) Marshal() ([]byte, error) {
	return json.Marshal(opt)
}

func (opt *ServerOptions) String() string {
	return toString(opt)
}

func (opt *ServerOptions) IsCompressionEnabled() bool {
	return opt.Compressor.Enable
}

func (opt *ServerOptions) IsEncryptionEnabled() bool {
	return opt.Encryptor.Enable
}

func (opt *ServerOptions) IsRegionGCEnabled() bool {
	return opt.Region.Enable
}

func (opt *ServerOptions) RegionGCInterval() time.Duration {
	return time.Duration(opt.Region.Second) * time.Second
}

func toString(opt *ServerOptions) string {
	bs, _ := opt.Marshal()
	return string(bs)
}

type ServerOptions struct {
	Port       int        `json:"port"`
	Path       string     `json:"path"`
	Debug      bool       `json:"debug"`
	LogPath    string     `json:"logpath"`
	Password   string     `json:"auth"`
	Region     Region     `json:"region"`
	Encryptor  Encryptor  `json:"encryptor"`
	Compressor Compressor `json:"compressor"`
	AllowIP    []string   `json:"allowip"`
}

type Region struct {
	Enable    bool  `json:"enable"`
	Second    int64 `json:"second"`
	Threshold uint8 `json:"threshold"`
}

type Encryptor struct {
	Enable bool   `json:"enable"`
	Secret string `json:"secret"`
}

type Compressor struct {
	Enable bool `json:"enable"`
}
