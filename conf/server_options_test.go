package conf

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestConfigLoad(t *testing.T) {
	// 创建一个临时目录用于测试
	tmpDir := t.TempDir()

	// 设置 Settings.Path 为临时目录
	Settings.Path = tmpDir

	// 创建一个配置文件并写入测试数据
	configFile := filepath.Join(tmpDir, "test-config.yaml")
	testConfigData := []byte(`
  port: 8080
  path: "/test/path"
  debug: true
`)

	err := os.WriteFile(configFile, testConfigData, 0644)
	if err != nil {
		t.Fatalf("Error writing test config file: %v", err)
	}

	// 调用 Load 函数
	loadedConfig := new(ServerOptions)
	err = Load(configFile, loadedConfig)
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	// 检查加载的配置是否正确
	expectedConfig := &ServerOptions{
		Port:  8080,
		Path:  "/test/path",
		Debug: true,
	}

	// 检查比较是否一致
	if !reflect.DeepEqual(loadedConfig, expectedConfig) {
		t.Errorf("Loaded config is not as expected.\nGot: %+v\nExpected: %+v", loadedConfig, expectedConfig)
	}
}

func TestConfigLoad_Error(t *testing.T) {

	// 创建一个临时目录用于测试
	Settings.Path = t.TempDir() + "/aaa/bbb"

	// 创建一个配置文件并写入测试数据
	configFile := filepath.Join(Settings.Path, "test-config.yaml")

	// 调用 Load 函数
	loadedConfig := new(ServerOptions)
	err := Load(configFile, loadedConfig)
	if err != nil {
		t.Log(err)
	}

}

func TestSavedAsConfig(t *testing.T) {

	// 创建一个临时目录用于测试
	tmpDir := t.TempDir()

	// 创建一个 ServerOptions 实例
	config := &ServerOptions{
		Port:     8080,
		Path:     tmpDir,
		Debug:    true,
		LogPath:  "/tmp/vasedb/out.log",
		Password: "password@123",
		Region: Region{
			Enable:    true,
			Second:    15000,
			Threshold: 3,
		},
		Encryptor: Encryptor{
			Enable: false,
			Secret: "test-secret",
		},
		Compressor: Compressor{
			Enable: false,
		},
		AllowIP: []string{"192.127.0.1", "192.127.0.2"},
	}

	_, err := os.Create(tmpDir + "/config.yaml")
	if err != nil {
		t.Error(err)
	}

	// 调用 Saved 函数
	err = config.SavedAs(tmpDir + "/config.yaml")

	if err != nil {
		t.Fatalf("Error saving config: %v", err)
	}
}

func TestSavedConfig(t *testing.T) {

	// 创建一个临时目录用于测试
	tmpDir := t.TempDir()

	os.Mkdir(filepath.Join(tmpDir, "etc"), FsPerm)

	// 创建一个 ServerOptions 实例
	config := &ServerOptions{

		Port:     8080,
		Path:     tmpDir,
		Debug:    true,
		LogPath:  "/tmp/vasedb/out.log",
		Password: "password@123",
		Region: Region{
			Enable:    true,
			Second:    15000,
			Threshold: 3,
		},
		Encryptor: Encryptor{
			Enable: false,
			Secret: "test-secret",
		},
		Compressor: Compressor{
			Enable: false,
		},
	}

	// 调用 Saved 函数
	err := config.Saved()

	if err != nil {
		t.Fatalf("Error saving config: %v", err)
	}
}

func TestSavedConfig_Error(t *testing.T) {

	// 创建一个临时目录用于测试
	tmpDir := t.TempDir()

	// 创建一个 ServerOptions 空实例
	var config *ServerOptions = nil

	// 调用 Saved 函数
	err := config.SavedAs(tmpDir)

	if err != nil {
		t.Log(err)
	}
}

func TestIsDefault(t *testing.T) {
	tests := []struct {
		name string
		flag string
		want bool
	}{
		{
			name: "successful", flag: "default.yaml", want: true,
		},
		{
			name: "failed", flag: "", want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasCustom(tt.flag); got != tt.want {
				t.Errorf("IsDefault() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInit(t *testing.T) {
	t.Run("Test DefaultConfig Unmarshal", func(t *testing.T) {
		err := Default.Unmarshal([]byte(DefaultConfigJSON))
		if err != nil {
			t.Log(err)
		}
	})

	t.Run("Test Settings Unmarshal", func(t *testing.T) {
		err := Settings.Unmarshal([]byte(DefaultConfigJSON))
		if err != nil {
			t.Log(err)
		}
	})

}

func TestServerOptions_Marshal(t *testing.T) {

	err := Settings.Unmarshal([]byte(DefaultConfigJSON))
	if err != nil {
		t.Error(err)
	}

	bytes, err := Settings.Marshal()

	if err != nil {
		t.Error(err)
	}

	if err := Default.Unmarshal(bytes); err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(Settings, Default) {
		t.Errorf("ServerOptions.Marshal() = %v, want %v", string(bytes), DefaultConfigJSON)
	}

}

func TestDefaultConfigInitialization(t *testing.T) {

	// 检查 DefaultConfig 是否被正确初始化
	if Default.Port != 2468 {
		t.Errorf("Expected DefaultConfig.Port to be 2468, but got %d", Default.Port)
	}

	// 检查 Settings 是否被正确初始化
	if Settings.Port != 2468 {
		t.Errorf("Expected Settings.Port to be 2468, but got %d", Settings.Port)
	}

}

func TestServerOptions_ToString(t *testing.T) {

	type fields struct {
		TestDB ServerOptions
	}

	vdb := ServerOptions{

		Port:     8080,
		Path:     "",
		Debug:    true,
		LogPath:  "/tmp/vasedb/out.log",
		Password: "password@123",
		Region: Region{
			Enable:    true,
			Second:    15000,
			Threshold: 3,
		},
		Encryptor: Encryptor{
			Enable: false,
			Secret: "test-secret",
		},
		Compressor: Compressor{
			Enable: false,
		},
	}

	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{name: "successful", fields: fields{TestDB: vdb}, want: vdb.String()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fields.TestDB.String(); got != tt.want {
				t.Errorf("ServerOptions.ToString() = %v, want %v", got, tt.want)
			}
		})
	}
}
