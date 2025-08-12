package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type AuthRequest struct {
	Key string `json:"key"`
}

type AuthResponse struct {
	Status int `json:"status"`
}

type KeyInfo struct {
	Valid      bool      `json:"valid"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	UsageCount int       `json:"usage_count"`
	MaxUsage   int       `json:"max_usage"`
}

// 模拟的key数据库
var (
	keyDatabase = make(map[string]*KeyInfo)
	dbMutex     = sync.RWMutex{}
)

// 初始化一些测试key
func initTestKeys() {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	// 生成一个有效的测试key
	testKey := generateRandomKey()
	keyDatabase[testKey] = &KeyInfo{
		Valid:      true,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(365 * 24 * time.Hour), // 1年有效期
		UsageCount: 0,
		MaxUsage:   1000, // 最多使用1000次
	}

	fmt.Printf("测试Key生成: %s (有效期1年，最多使用1000次)\n", testKey)

	// 生成一个无效的测试key
	invalidKey := generateRandomKey()
	keyDatabase[invalidKey] = &KeyInfo{
		Valid:      false,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(-24 * time.Hour), // 已过期
		UsageCount: 0,
		MaxUsage:   100,
	}

	fmt.Printf("无效Key生成: %s (已过期)\n", invalidKey)
}

// 生成随机key
func generateRandomKey() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// 验证key的有效性
func validateKey(key string) int {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	keyInfo, exists := keyDatabase[key]
	if !exists {
		log.Printf("Key不存在: %s", key)
		return -1 // key不存在
	}

	// 检查key是否有效
	if !keyInfo.Valid {
		log.Printf("Key已禁用: %s", key)
		return -1
	}

	// 检查是否过期
	if time.Now().After(keyInfo.ExpiresAt) {
		log.Printf("Key已过期: %s", key)
		return -1
	}

	// 检查使用次数限制
	if keyInfo.UsageCount >= keyInfo.MaxUsage {
		log.Printf("Key使用次数超限: %s (%d/%d)", key, keyInfo.UsageCount, keyInfo.MaxUsage)
		return -1
	}

	// 增加使用计数
	keyInfo.UsageCount++
	
	log.Printf("Key验证成功: %s (使用次数: %d/%d)", key, keyInfo.UsageCount, keyInfo.MaxUsage)
	return 1 // 验证成功
}

// 授权验证处理器
func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	// 设置CORS头
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	// 处理OPTIONS预检请求
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "仅支持POST方法", http.StatusMethodNotAllowed)
		return
	}

	var authReq AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
		log.Printf("JSON解析失败: %v", err)
		response := AuthResponse{Status: -1}
		json.NewEncoder(w).Encode(response)
		return
	}

	// 记录请求日志
	clientIP := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = xff
	}
	
	log.Printf("收到授权请求 - IP: %s, Key: %s", clientIP, authReq.Key)

	// 验证key
	status := validateKey(authReq.Key)
	
	response := AuthResponse{Status: status}
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("响应编码失败: %v", err)
	}

	if status == 1 {
		log.Printf("授权成功 - IP: %s, Key: %s", clientIP, authReq.Key)
	} else {
		log.Printf("授权失败 - IP: %s, Key: %s", clientIP, authReq.Key)
	}
}

// 健康检查处理器
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Unix(),
		"service":   "xzip-auth-server",
	}
	json.NewEncoder(w).Encode(response)
}

// 管理接口 - 添加新key
func addKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "仅支持POST方法", http.StatusMethodNotAllowed)
		return
	}

	// 生成新key
	newKey := generateRandomKey()
	
	dbMutex.Lock()
	keyDatabase[newKey] = &KeyInfo{
		Valid:      true,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(365 * 24 * time.Hour),
		UsageCount: 0,
		MaxUsage:   1000,
	}
	dbMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"key":     newKey,
		"message": "新Key已生成",
		"expires": time.Now().Add(365 * 24 * time.Hour),
	}
	
	json.NewEncoder(w).Encode(response)
	log.Printf("管理员生成新Key: %s", newKey)
}

// 统计信息处理器
func statsHandler(w http.ResponseWriter, r *http.Request) {
	dbMutex.RLock()
	defer dbMutex.RUnlock()

	totalKeys := len(keyDatabase)
	validKeys := 0
	totalUsage := 0

	for _, keyInfo := range keyDatabase {
		if keyInfo.Valid && time.Now().Before(keyInfo.ExpiresAt) {
			validKeys++
		}
		totalUsage += keyInfo.UsageCount
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"total_keys":   totalKeys,
		"valid_keys":   validKeys,
		"total_usage":  totalUsage,
		"server_time":  time.Now(),
	}
	
	json.NewEncoder(w).Encode(response)
}

func main() {
	fmt.Println("XZip 授权服务器 v1.0")
	fmt.Println("==============================")

	// 初始化测试数据
	initTestKeys()

	// 设置路由
	http.HandleFunc("/authorize", authorizeHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/admin/addkey", addKeyHandler)
	http.HandleFunc("/admin/stats", statsHandler)

	// 根路径处理
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `
		<h1>XZip 授权服务器</h1>
		<p>服务状态: 正常运行</p>
		<p>当前时间: %s</p>
		<h2>API接口:</h2>
		<ul>
			<li><a href="/health">健康检查</a></li>
			<li><a href="/admin/stats">统计信息</a></li>
			<li>POST /authorize - 客户端授权验证</li>
			<li>POST /admin/addkey - 生成新Key</li>
		</ul>
		`, time.Now().Format("2006-01-02 15:04:05"))
	})

	// 启动HTTPS服务器
	fmt.Println("正在启动HTTPS服务器...")
	fmt.Println("服务地址: https://localhost:8443")
	fmt.Println("证书文件: server.crt")
	fmt.Println("私钥文件: server.key")
	
	log.Fatal(http.ListenAndServeTLS(":8443", "server.crt", "server.key", nil))
}
