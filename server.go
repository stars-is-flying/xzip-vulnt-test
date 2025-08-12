package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	
	"github.com/alexmullins/zip"  // 使用支持密码的zip库
	"golang.org/x/term"
)

const (
	AuthURL = "https://xzip.com/authorize"
	KeyFile = ".xzip/key"
)

type AuthRequest struct {
	Key string `json:"key"`
}

type AuthResponse struct {
	Status int `json:"status"`
}

// 获取用户home目录下的key文件路径
func getKeyFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, KeyFile)
}

// 读取授权key
func readAuthKey() (string, error) {
	keyPath := getKeyFilePath()
	data, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("无法读取key文件 %s: %v", keyPath, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// 验证服务器证书域名
func verifyServerCertificate(resp *http.Response) error {
	if resp.TLS == nil {
		return fmt.Errorf("连接不是HTTPS")
	}
	
	for _, cert := range resp.TLS.PeerCertificates {
		for _, dnsName := range cert.DNSNames {
			if dnsName == "xzip.com" {
				return nil
			}
		}
		if cert.Subject.CommonName == "xzip.com" {
			return nil
		}
	}
	
	return fmt.Errorf("服务器证书域名验证失败，请确保连接到正确的xzip.com服务器")
}

// 验证授权
func validateAuth() error {
	key, err := readAuthKey()
	if err != nil {
		return fmt.Errorf("授权验证失败: %v", err)
	}

	authReq := AuthRequest{Key: key}
	jsonData, err := json.Marshal(authReq)
	if err != nil {
		return fmt.Errorf("序列化请求失败: %v", err)
	}

	// 创建HTTP客户端，禁用证书验证以便自定义验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Post(AuthURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("网络请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 验证服务器证书域名
	if err := verifyServerCertificate(resp); err != nil {
		return err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %v", err)
	}

	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return fmt.Errorf("解析响应失败: %v", err)
	}

	if authResp.Status == -1 {
		return fmt.Errorf("授权失败: 请到 https://xzip.com 购买正版key来正常使用软件")
	} else if authResp.Status != 1 {
		return fmt.Errorf("授权状态异常: 状态码 %d", authResp.Status)
	}

	fmt.Println("✅ 授权验证成功")
	return nil
}

// 获取密码输入
func getPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(bytePassword), nil
}

// 压缩文件夹到ZIP（支持密码）
func compressToZip(source, target, password string) error {
	fmt.Printf("正在压缩 %s 到 %s\n", source, target)
	
	zipFile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	defer archive.Close()

	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		// 设置相对路径
		relPath, _ := filepath.Rel(source, path)
		header.Name = relPath

		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}

		var writer io.Writer
		if password != "" {
			// 使用密码保护
			writer, err = archive.Encrypt(header.Name, password)
		} else {
			writer, err = archive.CreateHeader(header)
		}
		
		if err != nil {
			return err
		}

		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(writer, file)
			return err
		}

		return nil
	})
}

// 从ZIP解压缩（支持密码）
func extractFromZip(source, target, password string) error {
	fmt.Printf("正在解压缩 %s 到 %s\n", source, target)
	
	reader, err := zip.OpenReader(source)
	if err != nil {
		return err
	}
	defer reader.Close()

	os.MkdirAll(target, 0755)

	for _, file := range reader.File {
		path := filepath.Join(target, file.Name)
		
		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.FileInfo().Mode())
			continue
		}

		var fileReader io.ReadCloser
		if file.IsEncrypted() {
			if password == "" {
				return fmt.Errorf("文件 %s 需要密码，但未提供密码", file.Name)
			}
			fileReader, err = file.OpenWithPassword(password)
		} else {
			fileReader, err = file.Open()
		}
		
		if err != nil {
			return fmt.Errorf("打开文件 %s 失败: %v", file.Name, err)
		}
		defer fileReader.Close()

		os.MkdirAll(filepath.Dir(path), 0755)
		
		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()

		_, err = io.Copy(targetFile, fileReader)
		if err != nil {
			return err
		}
	}

	return nil
}

// 初始化key文件
func initKeyFile() error {
	keyPath := getKeyFilePath()
	keyDir := filepath.Dir(keyPath)
	
	// 创建.xzip目录
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}
	
	// 如果key文件不存在，创建一个空的
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		file, err := os.Create(keyPath)
		if err != nil {
			return fmt.Errorf("创建key文件失败: %v", err)
		}
		file.Close()
		
		fmt.Printf("已创建key文件: %s\n", keyPath)
		fmt.Println("请将您的授权key写入此文件")
		return fmt.Errorf("key文件为空，请先配置授权key")
	}
	
	return nil
}

func main() {
	fmt.Println("XZip 商业压缩软件 v1.0")
	fmt.Println("=================================")

	// 初始化key文件
	if err := initKeyFile(); err != nil {
		fmt.Printf("❌ 初始化失败: %v\n", err)
		return
	}

	// 验证授权
	if err := validateAuth(); err != nil {
		fmt.Printf("❌ %v\n", err)
		return
	}

	if len(os.Args) < 2 {
		fmt.Println("使用方法:")
		fmt.Println("  压缩: xzip compress <源文件/文件夹> <目标.zip文件>")
		fmt.Println("  解压: xzip extract <源.zip文件> <目标文件夹>")
		return
	}

	command := os.Args[1]

	switch command {
	case "compress":
		if len(os.Args) < 4 {
			fmt.Println("❌ 参数不足: xzip compress <源文件/文件夹> <目标.zip文件>")
			return
		}

		source := os.Args[2]
		target := os.Args[3]

		// 询问是否需要密码保护
		fmt.Print("是否需要密码保护? (y/n): ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		needPassword := strings.ToLower(scanner.Text()) == "y"

		var password string
		if needPassword {
			var err error
			password, err = getPassword("请输入密码: ")
			if err != nil {
				fmt.Printf("❌ 密码输入失败: %v\n", err)
				return
			}
		}

		if err := compressToZip(source, target, password); err != nil {
			fmt.Printf("❌ 压缩失败: %v\n", err)
		} else {
			fmt.Printf("✅ 压缩完成: %s\n", target)
		}

	case "extract":
		if len(os.Args) < 4 {
			fmt.Println("❌ 参数不足: xzip extract <源.zip文件> <目标文件夹>")
			return
		}

		source := os.Args[2]
		target := os.Args[3]

		// 询问是否需要密码
		fmt.Print("该压缩包是否有密码? (y/n): ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		hasPassword := strings.ToLower(scanner.Text()) == "y"

		var password string
		if hasPassword {
			var err error
			password, err = getPassword("请输入密码: ")
			if err != nil {
				fmt.Printf("❌ 密码输入失败: %v\n", err)
				return
			}
		}

		if err := extractFromZip(source, target, password); err != nil {
			fmt.Printf("❌ 解压缩失败: %v\n", err)
		} else {
			fmt.Printf("✅ 解压缩完成: %s\n", target)
		}

	default:
		fmt.Printf("❌ 未知命令: %s\n", command)
		fmt.Println("支持的命令: compress, extract")
	}
}
