package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/YangYang-Research/whale-sentinel-services/whale-sentinel-common-attack-detection/helper"
	"github.com/YangYang-Research/whale-sentinel-services/whale-sentinel-common-attack-detection/logger"
	"github.com/YangYang-Research/whale-sentinel-services/whale-sentinel-common-attack-detection/shared"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

var (
	ctx         = context.Background()
	log         *logrus.Logger
	redisClient *redis.Client
)

// Load environment variables
func init() {
	// Initialize the application logger
	log = logrus.New()
	log.SetFormatter(&logrus.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.DebugLevel)

	if err := godotenv.Load(); err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error loading .env file")
	} else {
		log.Info("Loaded environment variables from .env file")
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_HOST") + ":" + os.Getenv("REDIS_PORT"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})

	// Check Redis connection
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error connecting to Redis")
	} else {
		log.Info("Connected to Redis")
	}
}

func handlerHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// wsHandleDecoder decodes the input string
func wsHandleDecoder(input string) (string, error) {

	// Clean and decode the string
	cleanedString := strings.NewReplacer(`\\`, ``, `\%`, `%`, `<br/>`, ``).Replace(input)
	decodedString, err := url.QueryUnescape(cleanedString)
	if err != nil {
		return "", fmt.Errorf("failed to unescape string: %v", err)
	}
	decodedString = html.UnescapeString(decodedString)

	// Base64 decoding attempt
	base64Pattern := `( |,|;)base64,([A-Za-z0-9+/]*={0,2})`
	re := regexp.MustCompile(base64Pattern)
	matches := re.FindStringSubmatch(decodedString)
	if len(matches) > 2 {
		if decoded, err := base64.StdEncoding.DecodeString(matches[2]); err == nil {
			decodedString = strings.Replace(decodedString, matches[2], string(decoded), 1)
		}
	}

	// Convert to lowercase
	lowerString := strings.ToLower(decodedString)

	return lowerString, nil
}

func wsCrossSiteScriptingDetection(input string, patterns map[string]interface{}) (bool, error) {

	for _, p := range patterns {
		patternStr, ok := p.(string)
		if !ok {
			return false, fmt.Errorf("invalid pattern value: expected string, got %T", p)
		}

		re, err := regexp.Compile(patternStr)
		if err != nil {
			return false, fmt.Errorf("invalid regex pattern: %v", err)
		}

		if re.MatchString(input) {
			return true, nil
		}
	}
	return false, nil
}

func wsSQLInjectionDetection(input string, patterns map[string]interface{}) (bool, error) {

	for _, p := range patterns {
		patternStr, ok := p.(string)
		if !ok {
			return false, fmt.Errorf("invalid pattern value: expected string, got %T", p)
		}

		re, err := regexp.Compile(patternStr)
		if err != nil {
			return false, fmt.Errorf("invalid regex pattern: %v", err)
		}

		if re.MatchString(input) {
			return true, nil
		}
	}
	return false, nil
}

func wsHTTPVerbTamperingDetection(input string, pattern string) (bool, error) {

	// HTTP verb tampering detection patterns
	httpVerbPatterns := pattern

	re, err := regexp.Compile(httpVerbPatterns)
	if err != nil {
		return false, fmt.Errorf("invalid regex pattern: %v", err)
	}
	if !re.MatchString(input) {
		return true, nil
	}
	return false, nil
}

func wsLargeRequestDetection(input int, pattern float64) (bool, error) {
	// Large request detection patterns
	pattern = pattern * 1048576 // 2MB

	if input > int(pattern) {
		return true, nil
	}

	return false, nil
}

func wsUnknownAttackDetection(input string, patterns map[string]interface{}) (bool, error) {
	for k, v := range patterns {
		patternStr, ok := v.(string)
		if !ok {
			return false, fmt.Errorf("invalid pattern value at %s: expected string", k)
		}

		re, err := regexp.Compile(patternStr)
		if err != nil {
			return false, fmt.Errorf("invalid regex at key '%s': %v", k, err)
		}

		if re.MatchString(input) {
			return true, nil
		}
	}
	return false, nil
}

func wsInsecureRedirectDetection(self_domain string, redirect_domain string, patterns map[string]interface{}) (bool, error) {

	if redirect_domain == "" {
		return false, nil
	}

	// Parse redirect_domain để lấy phần host
	parsedURL, err := url.Parse(redirect_domain)
	if err != nil {
		return false, err
	}

	redirectHost := strings.ToLower(parsedURL.Host)
	selfHost := strings.ToLower(self_domain)

	// Nếu khác self_host thì kiểm tra tiếp
	if redirectHost != selfHost {
		// Nếu bật kiểm tra extend_domain thì kiểm tra trong danh sách
		if val, ok := patterns["extend_domain"].(bool); ok && val {
			if rawList, ok := patterns["patterns"].([]interface{}); ok {
				for _, p := range rawList {
					if domainStr, ok := p.(string); ok && strings.ToLower(domainStr) == redirectHost {
						return false, nil // domain nằm trong danh sách cho phép → an toàn
					}
				}
			}
		}
		// Không bật hoặc không nằm trong danh sách → không an toàn
		return true, nil
	}

	// redirect cùng domain → an toàn
	return false, nil
}

func wsInsecureFileUpload(files []interface{}, patterns map[string]interface{}) (bool, map[string]map[string]bool, error) {
	secureFileName := patterns["file_name"].(bool)
	// secureFileContent := patterns["file_content"].(bool)
	securFileSize := patterns["file_size"].(float64)
	secureFileType := true // patterns["file_type"].(bool)

	// Dùng để lưu kết quả kiểm tra của từng file
	allViolations := make(map[string]map[string]bool)

	foundViolation := false

	for _, file := range files {
		fileMap, ok := file.(map[string]interface{})
		if !ok {
			continue
		}

		fileName, _ := fileMap["FileName"].(string)
		fileSize, _ := fileMap["FileSize"].(float64)
		fileType, _ := fileMap["FileType"].(string)

		// Object lưu kết quả kiểm tra từng tiêu chí cho file hiện tại
		violations := map[string]bool{
			"file_name":    false,
			"file_size":    false,
			"file_type":    false,
			"file_content": false, // chưa xử lý
		}

		// 1. Tên file có nhiều dấu chấm → nghi ngờ (ví dụ: .txt.exe)
		if secureFileName && strings.Count(fileName, ".") > 1 {
			violations["file_name"] = true
			foundViolation = true
		}

		// 2. Kích thước file vượt quá giới hạn
		if securFileSize > 0 {
			maxSize := securFileSize * 1048576 // MB → byte
			if fileSize > maxSize {
				violations["file_size"] = true
				foundViolation = true
			}
		}

		// 3. Loại MIME không khớp với phần mở rộng
		if secureFileType {
			if dotIndex := strings.LastIndex(fileName, "."); dotIndex != -1 && dotIndex < len(fileName)-1 {
				ext := fileName[dotIndex+1:]
				expectedMime := mime.TypeByExtension("." + ext)
				if expectedMime == "" || !strings.HasPrefix(expectedMime, fileType) {
					violations["file_type"] = true
					foundViolation = true
				}
			}
		}

		// (Tùy chọn sau) 4. Kiểm tra nội dung file nếu cần

		// Lưu lại kết quả kiểm tra cho file này
		allViolations[fileName] = violations
	}

	return foundViolation, allViolations, nil
}

// sendErrorResponse sends a JSON error response
func sendErrorResponse(w http.ResponseWriter, message string, errorCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errorCode)
	json.NewEncoder(w).Encode(shared.ErrorResponse{
		Status:    "Error",
		Message:   message,
		ErrorCode: errorCode,
	})
}

// getAWSSecret retrieves the key based on the configuration
func getSecret(key string) (string, error) {
	awsRegion := os.Getenv("AWS_REGION")
	awsSecretName := os.Getenv("AWS_SECRET_NAME")
	awsSecretKeyName := key

	awsSecretVaule, err := helper.GetAWSSecret(awsRegion, awsSecretName, awsSecretKeyName)

	return awsSecretVaule, err
}

// apiKeyAuthMiddleware is a middleware that handles API Key authentication
func apiKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secretValue, err := getSecret(os.Getenv("WHALE_SENTINEL_SERVICE_SECRET_KEY_NAME"))
		if err != nil {
			sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Decode the Base64-encoded Authorization header
		authHeader = authHeader[len("Basic "):]
		decodedAuthHeader, err := base64.StdEncoding.DecodeString(authHeader)
		if err != nil {
			sendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		expectedAuthValue := fmt.Sprintf("ws:%s", secretValue)
		if string(decodedAuthHeader) != expectedAuthValue {
			sendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handlerRedis set and get value from Redis
func handlerRedis(key string, value string) (string, error) {
	if value == "" {
		// Get value from Redis
		val, err := redisClient.Get(ctx, key).Result()
		if err != nil {
			log.WithFields(logrus.Fields{
				"msg": err,
				"key": key,
			}).Error("Cannot GET - Not found key in Redis")
		}
		return val, err
	} else {
		// Set value in Redis
		err := redisClient.Set(ctx, key, value, 0).Err()
		if err != nil {
			log.WithFields(logrus.Fields{
				"msg": err,
			}).Error("Cannot SET - Cannot setting value in Redis")
		}
		return value, err
	}
}

// handleData processes incoming data and returns the response
func handleDetection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var (
		req shared.RequestBody
	)
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.EventInfo == "" || req.Payload.Data.AgentID == "" || req.Payload.Data.AgentName == "" {
		sendErrorResponse(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if req.Payload.Data.ClientInformation == (shared.ClientInformation{}) ||
		req.Payload.Data.HTTPRequest.Method == "" ||
		req.Payload.Data.HTTPRequest.URL == "" ||
		req.Payload.Data.HTTPRequest.Host == "" ||
		req.Payload.Data.HTTPRequest.Headers == (shared.HTTPRequestHeader{}) {
		sendErrorResponse(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Extract components from event_id
	_, serviceName, eventID, err := helper.ExtractEventInfo(req.EventInfo)
	if err != nil {
		sendErrorResponse(w, "Error extracting event_id: %v", http.StatusBadRequest)
		return
	}

	eventInfo := strings.Replace(req.EventInfo, "WS_GATEWAY_SERVICE", "WS_COMMON_ATTACK_DETECTION", -1)

	agentStatus, agentProfile, err := processProfile(req.Payload.Data.AgentID, req.Payload.Data.AgentName, "agent", req.EventInfo)
	if err != nil || agentStatus != "Success" || agentProfile == "" {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Warn("Agent profile retrieval failed.")

		response := shared.ResponseBody{
			Status:             agentStatus,
			Message:            "Failed to retrieve agent profile.",
			Data:               shared.ResponseData{},
			EventInfo:          eventInfo,
			RequestCreatedAt:   req.RequestCreatedAt,
			RequestProcessedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

		log.Infof("POST %v - 200", r.URL)
		// Log the request to the logg collector
		go func(Id string, Name string, eventInfo string, rawRequest interface{}) {
			// Log the request to the log collector
			logData := map[string]interface{}{
				"service":       "ws-common-attack-detection",
				"agent_id":      Id,
				"agent_name":    Name,
				"service_name":  "",
				"source":        strings.ToLower(serviceName),
				"destination":   "ws-common-attack-detection",
				"event_info":    eventInfo,
				"event_id":      eventID,
				"type":          "SERVICE_TO_SERVICE_EVENT",
				"action_type":   "ANALYSIS_REQUEST",
				"action_result": "ANALYSIS_REQUEST_FAILED_MISSING_AGENT_PROFILE",
				"action_status": "FAILED",
				"common_attack_detection": (map[string]bool{
					"cross_site_scripting_detection": false,
					"sql_injection_detection":        false,
					"http_verb_tampering_detection":  false,
					"http_large_request_detection":   false,
					"unknown_attack_detection":       false,
					"insecure_redirect_detection":    false,
					"insecure_file_upload":           false,
				}),
				"message":              "Cannot analyze request due to missing agent profile.",
				"request_created_at":   req.RequestCreatedAt,
				"request_processed_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
				"raw_request":          rawRequest,
			}

			logger.Log("info", logData)
		}(req.Payload.Data.AgentID, req.Payload.Data.AgentName, eventInfo, (req))
		return
	}

	serviceStatus, serviceProfile, err := processProfile("", "ws-common-attack-detection", "service", eventInfo)
	if err != nil || serviceStatus != "Success" || serviceProfile == "" {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Service profile retrieval failed.")

		response := shared.ResponseBody{
			Status:             agentStatus,
			Message:            "Failed to retrieve service profile.",
			Data:               shared.ResponseData{},
			EventInfo:          eventInfo,
			RequestCreatedAt:   req.RequestCreatedAt,
			RequestProcessedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

		log.Infof("POST %v - 200", r.URL)
		// Log the request to the logg collector
		go func(Id string, Name string, eventInfo string, rawRequest interface{}) {
			// Log the request to the log collector
			logData := map[string]interface{}{
				"service":       "ws-common-attack-detection",
				"agent_id":      "",
				"agent_name":    "",
				"service_name":  "ws-common-attack-detection",
				"source":        strings.ToLower(serviceName),
				"destination":   "ws-common-attack-detection",
				"event_info":    eventInfo,
				"event_id":      eventID,
				"type":          "SERVICE_TO_SERVICE_EVENT",
				"action_type":   "ANALYSIS_REQUEST",
				"action_result": "ANALYSIS_REQUEST_FAILED_MISSING_SERVICE_PROFILE",
				"action_status": "FAILED",
				"common_attack_detection": (map[string]bool{
					"cross_site_scripting_detection": false,
					"sql_injection_detection":        false,
					"http_verb_tampering_detection":  false,
					"http_large_request_detection":   false,
					"unknown_attack_detection":       false,
					"insecure_redirect_detection":    false,
					"insecure_file_upload":           false,
				}),
				"message":              "Cannot analyze request due to missing service profile.",
				"request_created_at":   req.RequestCreatedAt,
				"request_processed_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
				"raw_request":          rawRequest,
			}

			logger.Log("info", logData)
		}(req.Payload.Data.AgentID, req.Payload.Data.AgentName, eventInfo, (req))
		return
	}

	var agent shared.AgentProfileRaw
	var service shared.ServiceProfileRaw

	err = json.Unmarshal([]byte(agentProfile), &agent)
	if err != nil {
		log.WithField("msg", err).Error("Failed to parse agent configuration from Redis / ws-configuration-service")
		http.Error(w, "Whale Sentinel - Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = json.Unmarshal([]byte(serviceProfile), &service)
	if err != nil {
		log.WithField("msg", err).Error("Failed to parse service configuration from Redis / ws-configuration-service")
		http.Error(w, "Whale Sentinel - Internal Server Error", http.StatusInternalServerError)
		return
	}
	// Agent Running Profile
	agent_RunningProfile := agent.Profile["ws_module_common_attack_detection"].(map[string]interface{})

	// Service Running Profile
	service_DetectHTTPLargeRequest := service.Profile["detect_http_large_request"].(map[string]interface{})
	service_DetectHTTPVerbTampering := service.Profile["detect_http_verb_tampering"].(map[string]interface{})
	service_DetectXSS := service.Profile["detect_xss"].(map[string]interface{})
	service_DetectSQLI := service.Profile["detect_sqli"].(map[string]interface{})
	service_DetectUnknownAttack := service.Profile["detect_unknown_attack"].(map[string]interface{})
	service_DetectInsecureRedirect := service.Profile["detect_insecure_redirect"].(map[string]interface{})
	service_DetectInsecureFileUpload := service.Profile["detect_insecure_file_upload"].(map[string]interface{})

	// Process the rules
	var xssFound bool
	if agent_RunningProfile["detect_cross_site_scripting"].(bool) && service_DetectXSS["enable"].(bool) {
		payload := req.Payload.Data.HTTPRequest.QueryParams + req.Payload.Data.HTTPRequest.Body
		decodedPayload, err := wsHandleDecoder(payload)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
		xssFound, err = wsCrossSiteScriptingDetection(decodedPayload, service_DetectXSS["patterns"].(map[string]interface{}))
		if err != nil {
			sendErrorResponse(w, "Error processing xss detection", http.StatusInternalServerError)
			return
		}
	}

	var sqlInjectionFound bool
	if agent_RunningProfile["detect_sql_injection"].(bool) && service_DetectSQLI["enable"].(bool) {
		payload := req.Payload.Data.HTTPRequest.QueryParams + req.Payload.Data.HTTPRequest.Body
		decodedPayload, err := wsHandleDecoder(payload)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
		sqlInjectionFound, err = wsSQLInjectionDetection(decodedPayload, service_DetectSQLI["patterns"].(map[string]interface{}))
		if err != nil {
			sendErrorResponse(w, "Error processing data sqli detection", http.StatusInternalServerError)
			return
		}
	}

	var httpVerbTamperingFound bool
	if agent_RunningProfile["detect_http_verb_tampering"].(bool) && service_DetectHTTPVerbTampering["enable"].(bool) {
		httpVerbTamperingFound, err = wsHTTPVerbTamperingDetection(req.Payload.Data.HTTPRequest.Method, service_DetectHTTPVerbTampering["pattern"].(string))
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
	}

	var httpLargeRequestFound bool
	if agent_RunningProfile["detect_http_large_request"].(bool) && service_DetectHTTPLargeRequest["enable"].(bool) {
		httpLargeRequestFound, err = wsLargeRequestDetection(req.Payload.Data.HTTPRequest.Headers.ContentLength, service_DetectHTTPLargeRequest["pattern"].(float64))
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
	}

	var unknownAttackFound bool
	if agent_RunningProfile["detect_unknown_attack"].(bool) && service_DetectUnknownAttack["enable"].(bool) {
		payload := req.Payload.Data.HTTPRequest.QueryParams + req.Payload.Data.HTTPRequest.Body
		unknownAttackFound, err = wsUnknownAttackDetection(payload, service_DetectUnknownAttack["patterns"].(map[string]interface{}))
		if err != nil {
			fmt.Printf("DEBUG: %+v", err)
			sendErrorResponse(w, "Error processing data unknown attack detection", http.StatusInternalServerError)
			return
		}

	}

	var insecureRedirectFound bool
	if agent_RunningProfile["detect_insecure_redirect"].(bool) && service_DetectInsecureRedirect["enable"].(bool) {
		redirect_domain := req.Payload.Data.HTTPRequest.Headers.Referrer
		self_domain := req.Payload.Data.HTTPRequest.Host
		insecureRedirectFound, err = wsInsecureRedirectDetection(self_domain, redirect_domain, service_DetectInsecureRedirect)
		if err != nil {
			sendErrorResponse(w, "Error processing data insecure redirect detection", http.StatusInternalServerError)
			return
		}
	}

	var insecureFileUploadFound bool
	var _ map[string]map[string]bool
	if agent_RunningProfile["detect_insecure_file_upload"].(bool) && service_DetectInsecureFileUpload["enable"].(bool) {
		payload := req.Payload.Data.HTTPRequest.Files
		// Convert []shared.UploadedFile to []interface{}
		filesInterface := make([]interface{}, len(payload))
		for i, v := range payload {
			filesInterface[i] = map[string]interface{}{
				"FileName":    v.FileName,
				"FileSize":    float64(v.FileSize),
				"FileType":    v.FileType,
				"FileContent": v.FileContent,
				"FileHash256": v.FileHash256,
			}
		}

		insecureFileUploadFound, _, err = wsInsecureFileUpload(filesInterface, service_DetectInsecureFileUpload)
		if err != nil {
			sendErrorResponse(w, "Error processing data insecure file upload detection", http.StatusInternalServerError)
			return
		}
	}

	mapData := shared.ResponseData{
		CrossSiteScriptingDetection: xssFound,
		SQLInjectionDetection:       sqlInjectionFound,
		HTTPVerbTamperingDetection:  httpVerbTamperingFound,
		HTTPLargeRequestDetection:   httpLargeRequestFound,
		UnknownAttackDetection:      unknownAttackFound,
		InsecureRedirectDetection:   insecureRedirectFound,
		InsecureFileUploadDetection: insecureFileUploadFound,
	}

	var analysisResult string
	if xssFound || sqlInjectionFound || httpVerbTamperingFound || httpLargeRequestFound || unknownAttackFound {
		analysisResult = "ABNORMAL_REQUEST"
	} else {
		analysisResult = "NORNAL_REQUEST"
	}

	response := shared.ResponseBody{
		Status:             "Success",
		Message:            "Analysis completed successfully.",
		Data:               mapData,
		AnalysisResult:     analysisResult,
		EventInfo:          eventInfo,
		RequestCreatedAt:   req.RequestCreatedAt,
		RequestProcessedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Infof("POST %v - 200", r.URL)
	// Log the request to the logg collector
	go func(Id string, Name string, eventInfo string, rawRequest interface{}) {
		// Log the request to the log collector
		logData := map[string]interface{}{
			"service":       "ws-common-attack-detection",
			"agent_id":      Id,
			"agent_name":    Name,
			"service_name":  "ws-common-attack-detection",
			"source":        strings.ToLower(serviceName),
			"destination":   "ws-common-attack-detection",
			"event_info":    eventInfo,
			"event_id":      eventID,
			"type":          "SERVICE_TO_SERVICE_EVENT",
			"action_type":   "ANALYSIS_REQUEST",
			"action_result": "SERVICE_ANALYSIS_SUCCESSED_" + analysisResult,
			"action_status": "SUCCESSED",
			"common_attack_detection": (map[string]bool{
				"cross_site_scripting_detection": xssFound,
				"sql_injection_detection":        sqlInjectionFound,
				"http_verb_tampering_detection":  httpVerbTamperingFound,
				"http_large_request_detection":   httpLargeRequestFound,
				"unknown_attack_detection":       unknownAttackFound,
				"insecure_redirect_detection":    insecureRedirectFound,
				"insecure_file_upload":           insecureFileUploadFound,
			}),
			"message":              "Analysis completed successfully.",
			"request_created_at":   req.RequestCreatedAt,
			"request_processed_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"raw_request":          rawRequest,
		}

		logger.Log("info", logData)
	}(req.Payload.Data.AgentID, req.Payload.Data.AgentName, eventInfo, (req))
}

func makeHTTPRequest(url, endpoint string, body interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	secretValue, err := getSecret(os.Getenv("WHALE_SENTINEL_SERVICE_SECRET_KEY_NAME"))
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %v", err)
	}

	req, err := http.NewRequest("POST", url+endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	auth := "ws:" + secretValue
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

	verifyTLS, err := strconv.ParseBool(os.Getenv("WHALE_SENTINEL_VERIFY_TLS"))
	if err != nil {
		log.Fatalf("Invalid boolean value for WHALE_SENTINEL_VERIFY_TLS: %v", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyTLS},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call endpoint: %v", err)
	}
	defer resp.Body.Close()

	log.Infof("POST %v - %v", url+endpoint, resp.StatusCode)
	return io.ReadAll(resp.Body)

}

func processProfile(id string, name string, _type string, eventInfo string) (string, string, error) {
	getProfile, err := handlerRedis(name, "")
	if err != nil {
		log.Warn("Cannot getting " + _type + " profile from Redis. Let getting " + _type + " profile from ws-configuration-service")
	}

	if getProfile == "" {
		requestBody := map[string]interface{}{
			"event_info": eventInfo,
			"payload": map[string]interface{}{
				"data": map[string]interface{}{
					"type": _type,
					"name": name,
					"id":   id,
				},
			},
			"request_created_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		}
		responseData, err := makeHTTPRequest(os.Getenv("WS_MODULE_CONFIGURATION_SERVICE_URL"), os.Getenv("WS_MODULE_CONFIGURATION_SERVICE_ENDPOINT")+"/profile", requestBody)

		if err != nil {
			log.WithFields(logrus.Fields{
				"msg": err,
			}).Error("Error calling WS Module Configuration Service")
			return "Error", "", fmt.Errorf("failed to call WS Module Configuration Service: %v", err)
		}

		var response map[string]interface{}

		if err := json.Unmarshal(responseData, &response); err != nil {
			return "Error", "", fmt.Errorf("failed to parse response data: %v", err)
		}

		data := response["data"].(map[string]interface{})
		return response["status"].(string), data["profile"].(string), nil
	}
	return "Success", getProfile, nil
}

func main() {
	log.Info("WS Common Attack Detection is running on port 5003...")
	// Initialize the logger
	logMaxSize, _ := strconv.Atoi(os.Getenv("LOG_MAX_SIZE"))
	logMaxBackups, _ := strconv.Atoi(os.Getenv("LOG_MAX_BACKUPS"))
	logMaxAge, _ := strconv.Atoi(os.Getenv("LOG_MAX_AGE"))
	logCompression, _ := strconv.ParseBool(os.Getenv("LOG_COMPRESSION"))
	logger.SetupWSLogger("ws-common-attack-detection", logMaxSize, logMaxBackups, logMaxAge, logCompression)

	// Wrap the handler with a 30-second timeout
	timeoutHandlerHealth := http.TimeoutHandler(http.HandlerFunc(handlerHealth), 30*time.Second, "Request time out")
	timeoutHandler := http.TimeoutHandler(http.HandlerFunc(handleDetection), 30*time.Second, "Request timed out")

	// Register the timeout handler
	http.Handle("/health", timeoutHandlerHealth)
	http.Handle("/api/v1/ws/services/common-attack-detection", apiKeyAuthMiddleware(timeoutHandler))
	log.Fatal(http.ListenAndServe(":5003", nil))
}
