package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

// var outputDir = "video"

var oldName = ""

// FileInfo 定义文件信息的结构体
type FileInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// 定义一个密钥用于签名和验证令牌
var jwtSecret = []byte("your_secret_key")

// LoginRequest 定义登录请求和响应结构体
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token  string    `json:"token"`
	Expiry time.Time `json:"expiry"`
}

// Response 定义通用的响应结构体
type Response struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

// 假设的用户名和密码
var validUsername = "admin"
var validPassword = "password123"

var clients = make(map[*websocket.Conn]bool) // 存储 WebSocket 连接
var muClients sync.Mutex

// CustomClaims 自定义声明结构体（为了包含更多信息）
type CustomClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

const (
	outputDir   = "./uploads"
	videoDir    = "./video"
	tempMerged  = "temp_merged.mp4"
	fileListTxt = "filelist.txt"
)

var mu sync.Mutex

// 生成 JWT 令牌
func generateJWT(username string) (string, error) {
	claims := CustomClaims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)), // 设置过期时间为1小时
			Issuer:    "your_app_name",                                   // 发行者
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 使用密钥签名 token
	return token.SignedString(jwtSecret)
}

// 解析 JWT 令牌
func parseJWT(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Upgrade(w, r, nil, 1024, 1024)
	if err != nil {
		http.Error(w, "WebSocket upgrade failed", http.StatusInternalServerError)
		return
	}

	muClients.Lock()
	clients[conn] = true
	muClients.Unlock()

	defer func() {
		muClients.Lock()
		delete(clients, conn)
		muClients.Unlock()
		conn.Close()
	}()

	// for {
	//     _, _, err := conn.ReadMessage()
	//     if err != nil {
	//         break
	//     }
	// }

	// 启动一个 goroutine，每秒发送一次消息
	// 	go func() {
	// 		ticker := time.NewTicker(1 * time.Second)
	// 		defer ticker.Stop()

	// 		for range ticker.C {
	// 			// 测试消息
	// 			message := "Test message: " + time.Now().Format("15:04:05")
	// 			if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
	// 				log.Printf("Failed to send message: %v", err)
	// 				return
	// 			}
	// 		}
	// 	}()

	// 保持 WebSocket 连接
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Connection closed: %v", err)
			break
		}
	}
}

// 登录处理程序
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// 检查是否为POST请求
	if r.Method != http.MethodPost {
		sendErrorResponse(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
		return
	}

	var loginReq LoginRequest

	// 解析请求体
	err := json.NewDecoder(r.Body).Decode(&loginReq)
	if err != nil {
		sendErrorResponse(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// 验证用户名和密码
	if loginReq.Username != validUsername || loginReq.Password != validPassword {
		sendErrorResponse(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	// 生成JWT令牌
	token, err := generateJWT(loginReq.Username)
	if err != nil {
		sendErrorResponse(w, http.StatusInternalServerError, "Error generating token")
		return
	}

	expiry := time.Now().Add(1 * time.Hour) // 设置令牌过期时间

	// 构建响应数据
	response := Response{
		Code: 200,
		Msg:  "Login successful",
		Data: LoginResponse{
			Token:  token,
			Expiry: expiry,
		},
	}

	// 返回 JSON 格式的响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// 解析 token 接口
func parseTokenHandler(r *http.Request) (*CustomClaims, error) {
	// 从请求头获取 token
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		return nil, fmt.Errorf("请登录")
	}

	// 检查 token 的前缀 "Bearer "，并去掉它
	if !strings.HasPrefix(tokenString, "Bearer ") {
		return nil, fmt.Errorf("token格式错误")
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	// 解析 token
	claims, err := parseJWT(tokenString)
	if err != nil {
		return nil, fmt.Errorf("token不合法或已过期，请重新登录")
	}

	return claims, nil
}

// 统一的错误响应函数
func sendErrorResponse(w http.ResponseWriter, code int, message string) {
	response := Response{
		Code: code,
		Msg:  message,
		Data: nil,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(response)
}

// 获取 video 文件夹下的所有文件并返回标准的 JSON 响应
func videoFilesHandler(w http.ResponseWriter, r *http.Request) {
	// 验证 Token
	_, err := parseTokenHandler(r)
	if err != nil {
		sendErrorResponse(w, http.StatusUnauthorized, err.Error())
		return
	}
	// 获取当前工作目录
	dir, err := os.Getwd()
	if err != nil {
		// 构建错误响应
		response := Response{
			Code: 500,
			Msg:  "Unable to get current directory",
			Data: nil,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// 拼接 video 文件夹路径
	videoDir := filepath.Join(dir, "video")

	// 读取 video 文件夹内容
	files, err := os.ReadDir(videoDir)
	if err != nil {
		// 构建错误响应
		response := Response{
			Code: 500,
			Msg:  "Unable to read video directory",
			Data: nil,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// 创建用于存储文件信息的切片
	var fileInfos []FileInfo

	// 遍历文件夹中的文件
	for _, file := range files {
		if !file.IsDir() { // 检查是否是文件
			fileInfos = append(fileInfos, FileInfo{
				Name: file.Name(),
				Path: "http://" + filepath.Join("view.raxan.xyz/video", file.Name()), // 获取文件路径
			})
		}
	}

	// 构建成功响应
	response := Response{
		Code: 200,
		Msg:  "Success",
		Data: fileInfos,
	}

	// 设置响应头为 JSON 格式
	w.Header().Set("Content-Type", "application/json")

	// 返回 JSON 响应
	json.NewEncoder(w).Encode(response)
}

// func handleUpload(w http.ResponseWriter, r *http.Request) {
// 	filename := "today.mp4"
// 	// 	index := strings.Index(filename, "_")
// 	// 	if index != -1 {
// 	// 		// 直接输出_前面的内容
// 	// 		filename = filename[:index] + ".mp4"
// 	// 	} else {
// 	// 		fmt.Println("未找到'_'字符")
// 	// 	}
// 	//filename := "aaa.mp4"
// 	// 上传视频块
// 	file, _, err := r.FormFile("videoChunk")
// 	if err != nil {
// 		fmt.Println("Error retrieving the file:", err)
// 		http.Error(w, "Failed to get video chunk", http.StatusBadRequest)
// 		return
// 	}
// 	defer file.Close()
// 	outputFile := filepath.Join(outputDir, filename)
// 	// 将块追加到目标文件中
// 	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	if err != nil {
// 		http.Error(w, "Failed to open output file", http.StatusInternalServerError)
// 		return
// 	}
// 	defer f.Close()

// 	// 写入数据
// 	_, err = io.Copy(f, file)
// 	if err != nil {
// 		http.Error(w, "Failed to append video chunk", http.StatusInternalServerError)
// 		return
// 	}

// 	fmt.Fprintln(w, "Video chunk uploaded")
// }

func delHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("fileName")
	err := os.Remove("video/" + filename)
	if err != nil {
		fmt.Println("删除文件失败:", err)
	} else {
		fmt.Println("文件已成功删除")
	}
	response := Response{
		Code: 200,
		Msg:  "Success",
		Data: filename,
	}

	// 设置响应头为 JSON 格式
	w.Header().Set("Content-Type", "application/json")

	// 返回 JSON 响应
	json.NewEncoder(w).Encode(response)
}

// 处理视频块上传
func handleUpload(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("fileName") + ".mp4"
	// 如果hls目录不存在，则创建
	hash := md5.Sum([]byte(filename))
	md5Str := hex.EncodeToString(hash[:])
	hlsOutputDir := filepath.Join(outputDir, md5Str)

	if _, err := os.Stat(hlsOutputDir); os.IsNotExist(err) {
		if err := os.MkdirAll(hlsOutputDir, 0755); err != nil {
			http.Error(w, fmt.Sprintf("failed to create hash output directory: %v", err), http.StatusBadRequest)
			return
		}
	}

	file, _, err := r.FormFile("videoChunk")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get video chunk: %v", err), http.StatusBadRequest)
		return
	}
	defer file.Close()

	tempFile, err := os.CreateTemp(hlsOutputDir, "*.mp4")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create temp file: %v", err), http.StatusInternalServerError)
		return
	}
	defer tempFile.Close()

	// 保存上传的块
	if _, err := io.Copy(tempFile, file); err != nil {
		http.Error(w, fmt.Sprintf("Failed to write video chunk: %v", err), http.StatusInternalServerError)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	// 更新文件列表
	appendErr := appendToFileList(tempFile.Name(), hlsOutputDir)
	if appendErr != nil {
		http.Error(w, fmt.Sprintf("Failed to update file list: %v", appendErr), http.StatusInternalServerError)
		return
	}

	// 增量合并
	mergeErr := incrementalMerge(filename, hlsOutputDir)
	if mergeErr != nil {
		http.Error(w, fmt.Sprintf("Failed to merge video chunk: %v", mergeErr), http.StatusInternalServerError)
		return
	}

	// 生成HLS流
	// hlsErr := generateHLS(filename)
	// if hlsErr != nil {
	//     http.Error(w, fmt.Sprintf("Failed to generate HLS: %v", hlsErr), http.StatusInternalServerError)
	//     return
	// }

	fmt.Fprintln(w, "Video chunk uploaded and merged")
}

// 将新文件追加到 filelist.txt 中
func appendToFileList(filename, hlsOutputDir string) error {
	f, err := os.OpenFile(filepath.Join(hlsOutputDir, fileListTxt), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to update filelist: %v", err)
	}
	defer f.Close()

	replaced := strings.ReplaceAll(filename, hlsOutputDir+"/", "")
	_, err = f.WriteString(fmt.Sprintf("file '%s'\n", replaced))
	if err != nil {
		return fmt.Errorf("error writing to filelist: %v", err)
	}

	return nil
}

// 增量合并视频块
func incrementalMerge(filename, hlsOutputDir string) error {
	// 	tempMergedPath := filepath.Join(hlsOutputDir, tempMerged)
	outputFilePath := filepath.Join(videoDir, filename)

	// 使用 FFmpeg 合并
	// 	cmd := exec.Command("/usr/local/ffmpeg/bin/ffmpeg", "-f", "concat", "-safe", "0", "-i", filepath.Join(hlsOutputDir, fileListTxt), "-c", "copy", tempMergedPath)
	// 	output, err := cmd.CombinedOutput() // 捕获所有输出，包括错误
	// 	if err != nil {
	// 		return fmt.Errorf("ffmpeg merge failed: %v, output: %s", err, string(output))
	// 	}

	// 重命名最终的合并文件
	// 	if renameErr := os.Rename(tempMergedPath, outputFilePath); renameErr != nil {
	// 		return fmt.Errorf("failed to rename merged file: %v", renameErr)
	// 	}

	// 提取图片帧并发送
	go extractFramesAndSend(outputFilePath)

	return nil
}

// 视频转图片
func extractFramesAndSend(videoPath string) {
	// 提取帧率信息
	// 	frameRate := extractFrameRate(videoPath)
	fmt.Printf("Video frame rate: %s\n", videoPath)

	// 使用 FFmpeg 提取图片帧
	// cmd := exec.Command("/usr/local/ffmpeg/bin/ffmpeg", "-i", videoPath, "-vf", "fps=10", "-f", "image2pipe", "-vcodec", "mjpeg", "pipe:1")
	// stdout, err := cmd.StdoutPipe()
	// if err != nil {
	//     fmt.Println("Error creating FFmpeg pipe:", err)
	//     return
	// }

	// err = cmd.Start()
	// if err != nil {
	//     fmt.Println("Error starting FFmpeg:", err)
	//     return
	// }
	// defer cmd.Wait()

	// buf := &bytes.Buffer{}
	// for {
	//     buf.Reset()
	//     _, err := io.CopyN(buf, stdout, 1024*1024) // 读取图片块
	//     if err != nil {
	//         if err == io.EOF {
	//             break
	//         }
	//         fmt.Println("Error reading FFmpeg output:", err)
	//         break
	//     }

	//     imageData := buf.Bytes()

	//     // 广播图片数据
	//     muClients.Lock()
	//     for client := range clients {
	//         fmt.Println(client)
	//         err := client.WriteMessage(websocket.BinaryMessage, imageData)
	//         if err != nil {
	//             fmt.Println("WebSocket send error:", err)
	//             client.Close()
	//             delete(clients, client)
	//         }
	//     }
	//     muClients.Unlock()
	// }

	// 使用 FFmpeg 提取图片帧（30fps）
	cmd := exec.Command("/usr/local/ffmpeg/bin/ffmpeg", "-i", videoPath, "-vf", "fps=30,scale=270:-1", "-f", "image2pipe", "-vcodec", "mjpeg", "pipe:1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		println("Error creating FFmpeg pipe:", err.Error())
		return
	}

	err = cmd.Start()
	if err != nil {
		println("Error starting FFmpeg:", err.Error())
		return
	}
	defer cmd.Wait()

	// 解码并发送帧
	for {
		img, err := jpeg.Decode(stdout)
		if err != nil {
			if err == io.EOF {
				break
			}
			println("Error decoding JPEG frame:", err.Error())
			continue
		}

		// 编码图片为 JPEG 数据
		imageData, err := encodeToJPEG(img)
		if err != nil {
			println("Error encoding JPEG:", err.Error())
			continue
		}

		// 将图片数据发送给所有客户端
		muClients.Lock()
		for client := range clients {
			err := client.WriteMessage(websocket.BinaryMessage, imageData)
			if err != nil {
				println("WebSocket send error:", err.Error())
				client.Close()
				delete(clients, client)
			}
		}
		muClients.Unlock()
	}
}

// Helper function to encode an image to JPEG format
func encodeToJPEG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	err := jpeg.Encode(&buf, img, nil) // 默认使用无额外配置的 JPEG 编码器
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// 提取视频帧率
func extractFrameRate(videoPath string) string {
	// 使用 ffprobe 提取帧率信息
	cmd := exec.Command("/usr/local/ffmpeg/bin/ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=r_frame_rate", "-of", "default=noprint_wrappers=1:nokey=1", videoPath)
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error fetching frame rate:", err)
		return "unknown"
	}

	// 解析帧率 (e.g., "24000/1001")
	frameRate := string(bytes.TrimSpace(output))
	return frameRate
}

// func generateHLS(filename string) error {
//     outputFilePath := filepath.Join(outputDir, filename)
//     hlsOutputDir := filepath.Join(outputDir, "hls")

//     // 如果hls目录不存在，则创建
//     if _, err := os.Stat(hlsOutputDir); os.IsNotExist(err) {
//         if err := os.MkdirAll(hlsOutputDir, 0755); err != nil {
//             return fmt.Errorf("failed to create HLS output directory: %v", err)
//         }
//     }

//     // 使用FFmpeg生成HLS流
//     cmd := exec.Command("/usr/local/ffmpeg/bin/ffmpeg", "-i", outputFilePath,
//         "-c", "copy", "-bsf:v", "h264_mp4toannexb", "-f", "hls",
//         "-hls_time", "1",            // 每个切片的时长为1秒
//         "-hls_list_size", "0",        // 保持所有切片
//         "-hls_segment_filename", filepath.Join(hlsOutputDir, "segment_%03d.ts"),
//         filepath.Join(hlsOutputDir, "playlist.m3u8"))

//     output, err := cmd.CombinedOutput()
//     if err != nil {
//         return fmt.Errorf("ffmpeg HLS generation failed: %v, output: %s", err, string(output))
//     }

//     return nil
// }

func main() {
	http.HandleFunc("/upload", handleUpload)
	http.HandleFunc("/videoList", videoFilesHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/del", delHandler)
	http.HandleFunc("/ws", wsHandler)
	port := 8003
	fmt.Printf("Server started at :%d\n", port)
	http.ListenAndServe(":"+strconv.Itoa(port), nil)
}
