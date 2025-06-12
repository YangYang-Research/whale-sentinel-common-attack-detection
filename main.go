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

func wsCrossSiteScriptingDetection(input string) (bool, error) {

	// XSS detection patterns
	xssPatterns := []string{
		`(?:https?://|//)[^\s/]+\.js`,                                                   // Detects .js files
		`((%3C)|<)((%2F)|/)*[a-z0-9%]+((%3E)|>)`,                                        // Detects <tag>
		`((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)`, // Detects <img>
		`((%3C)|<)[^\n]+((%3E)|>)`,                                                      // Detects <tag>
		`(?i)<script[^>]*>.*?</script>`,                                                 // Detects <script> tags
		`(?i)on\w+\s*=\s*["']?[^"'>]+["']?`,                                             // Detects inline event handlers like onclick=
		`(?i)javascript\s*:\s*[^"'>\s]+`,                                                // Detects javascript: in URLs
		`(?i)eval\s*\(`,                                                                 // Detects eval(
		`(?i)document\.cookie`,                                                          // Detects document.cookie
		`(?i)alert\s*\(`,                                                                // Detects alert(
		`(?i)prompt\s*\(`,                                                               // Detects prompt(
		`(?i)confirm\s*\(`,                                                              // Detects confirm(
		`(?i)onload\s*=\s*[^"'>]+`,                                                      // Detects onload=
		`(?i)onerror\s*=\s*[^"'>]+`,                                                     // Detects onerror=
		`(?i)onmouseover\s*=\s*[^"'>]+`,                                                 // Detects onmouseover=
		`(?i)onfocus\s*=\s*[^"'>]+`,                                                     // Detects onfocus=
		`(?i)onblur\s*=\s*[^"'>]+`,                                                      // Detects onblur=
		`(?i)onchange\s*=\s*[^"'>]+`,                                                    // Detects onchange=
		`(?i)onsubmit\s*=\s*[^"'>]+`,                                                    // Detects onsubmit=
		`(?i)onreset\s*=\s*[^"'>]+`,                                                     // Detects onreset=
		`(?i)onselect\s*=\s*[^"'>]+`,                                                    // Detects onselect=
		`(?i)onkeydown\s*=\s*[^"'>]+`,                                                   // Detects onkeydown=
		`(?i)onkeypress\s*=\s*[^"'>]+`,                                                  // Detects onkeypress=
		`(?i)onmousedown\s*=\s*[^"'>]+`,                                                 // Detects onmousedown=
		`(?i)onmouseup\s*=\s*[^"'>]+`,                                                   // Detects onmouseup=
		`(?i)onmousemove\s*=\s*[^"'>]+`,                                                 // Detects onmousemove=
		`(?i)onmouseout\s*=\s*[^"'>]+`,                                                  // Detects onmouseout=
		`(?i)onmouseenter\s*=\s*[^"'>]+`,                                                // Detects onmouseenter=
		`(?i)onmouseleave\s*=\s*[^"'>]+`,                                                // Detects onmouseleave=
		`(?i)oncontextmenu\s*=\s*[^"'>]+`,                                               // Detects oncontextmenu=
		`(?i)onresize\s*=\s*[^"'>]+`,                                                    // Detects onresize=
		`(?i)onscroll\s*=\s*[^"'>]+`,                                                    // Detects onscroll=
		`(?i)onwheel\s*=\s*[^"'>]+`,                                                     // Detects onwheel=
		`(?i)oncopy\s*=\s*[^"'>]+`,                                                      // Detects oncopy=
		`(?i)oncut\s*=\s*[^"'>]+`,                                                       // Detects oncut=
		`(?i)onpaste\s*=\s*[^"'>]+`,                                                     // Detects onpaste=
		`(?i)onbeforeunload\s*=\s*[^"'>]+`,                                              // Detects onbeforeunload=
		`(?i)onhashchange\s*=\s*[^"'>]+`,                                                // Detects onhashchange=
		`(?i)onmessage\s*=\s*[^"'>]+`,                                                   // Detects onmessage=
		`(?i)onoffline\s*=\s*[^"'>]+`,                                                   // Detects onoffline=
		`(?i)ononline\s*=\s*[^"'>]+`,                                                    // Detects ononline=
		`(?i)onpagehide\s*=\s*[^"'>]+`,                                                  // Detects onpagehide=
		`(?i)onpageshow\s*=\s*[^"'>]+`,                                                  // Detects onpageshow=
		`(?i)onpopstate\s*=\s*[^"'>]+`,                                                  // Detects onpopstate=
		`(?i)onstorage\s*=\s*[^"'>]+`,                                                   // Detects onstorage=
		`(?i)onunload\s*=\s*[^"'>]+`,                                                    // Detects onunload=
		`(?i)onerror\s*=\s*[^"'>]+`,                                                     // Detects onerror=
		`(?i)onhashchange\s*=\s*[^"'>]+`,                                                // Detects onhashchange=
		`(?i)onload\s*=\s*[^"'>]+`,                                                      // Detects onload=
		`(?i)onresize\s*=\s*[^"'>]+`,                                                    // Detects onresize=
		`(?i)onunload\s*=\s*[^"'>]+`,                                                    // Detects onunload=
		`(?i)onpageshow\s*=\s*[^"'>]+`,                                                  // Detects onpageshow=
		`(?i)onpagehide\s*=\s*[^"'>]+`,                                                  // Detects onpagehide=
		`(?i)onpopstate\s*=\s*[^"'>]+`,                                                  // Detects onpopstate=
		`(?i)ononline\s*=\s*[^"'>]+`,                                                    // Detects ononline=
		`(?i)onoffline\s*=\s*[^"'>]+`,                                                   // Detects onoffline=
		`(?i)onmessage\s*=\s*[^"'>]+`,                                                   // Detects onmessage=
		`(?i)onstorage\s*=\s*[^"'>]+`,                                                   // Detects onstorage=
		`(?i)onbeforeunload\s*=\s*[^"'>]+`,                                              // Detects onbeforeunload=
		`(?i)onunload\s*=\s*[^"'>]+`,                                                    // Detects onunload=
		`(?i)oninput\s*=\s*[^"'>]+`,                                                     // Detects oninput=
		`(?i)oninvalid\s*=\s*[^"'>]+`,                                                   // Detects oninvalid=
		`(?i)onsearch\s*=\s*[^"'>]+`,                                                    // Detects onsearch=
		`(?i)onkeyup\s*=\s*[^"'>]+`,                                                     // Detects onkeyup=
		`(?i)oncut\s*=\s*[^"'>]+`,                                                       // Detects oncut=
		`(?i)onpaste\s*=\s*[^"'>]+`,                                                     // Detects onpaste=
		`(?i)onabort\s*=\s*[^"'>]+`,                                                     // Detects onabort=
		`(?i)oncanplay\s*=\s*[^"'>]+`,                                                   // Detects oncanplay=
		`(?i)oncanplaythrough\s*=\s*[^"'>]+`,                                            // Detects oncanplaythrough=
		`(?i)ondurationchange\s*=\s*[^"'>]+`,                                            // Detects ondurationchange=
		`(?i)onemptied\s*=\s*[^"'>]+`,                                                   // Detects onemptied=
		`(?i)onended\s*=\s*[^"'>]+`,                                                     // Detects onended=
		`(?i)onerror\s*=\s*[^"'>]+`,                                                     // Detects onerror=
		`(?i)onloadeddata\s*=\s*[^"'>]+`,                                                // Detects onloadeddata=
		`(?i)onloadedmetadata\s*=\s*[^"'>]+`,                                            // Detects onloadedmetadata=
		`(?i)onloadstart\s*=\s*[^"'>]+`,                                                 // Detects onloadstart=
		`(?i)onpause\s*=\s*[^"'>]+`,                                                     // Detects onpause=
		`(?i)onplay\s*=\s*[^"'>]+`,                                                      // Detects onplay=
		`(?i)onplaying\s*=\s*[^"'>]+`,                                                   // Detects onplaying=
		`(?i)onprogress\s*=\s*[^"'>]+`,                                                  // Detects onprogress=
		`(?i)onratechange\s*=\s*[^"'>]+`,                                                // Detects onratechange=
		`(?i)onseeked\s*=\s*[^"'>]+`,                                                    // Detects onseeked=
		`(?i)onseeking\s*=\s*[^"'>]+`,                                                   // Detects onseeking=
		`(?i)onstalled\s*=\s*[^"'>]+`,                                                   // Detects onstalled=
		`(?i)onsuspend\s*=\s*[^"'>]+`,                                                   // Detects onsuspend=
		`(?i)ontimeupdate\s*=\s*[^"'>]+`,                                                // Detects ontimeupdate=
		`(?i)onvolumechange\s*=\s*[^"'>]+`,                                              // Detects onvolumechange=
		`(?i)onwaiting\s*=\s*[^"'>]+`,                                                   // Detects onwaiting=
		`(?i)onshow\s*=\s*[^"'>]+`,                                                      // Detects onshow=
		`(?i)onvisibilitychange\s*=\s*[^"'>]+`,                                          // Detects onvisibilitychange=
		`(?i)onanimationstart\s*=\s*[^"'>]+`,                                            // Detects onanimationstart=
		`(?i)onanimationend\s*=\s*[^"'>]+`,                                              // Detects onanimationend=
		`(?i)onanimationiteration\s*=\s*[^"'>]+`,                                        // Detects onanimationiteration=
		`(?i)ontransitionend\s*=\s*[^"'>]+`,                                             // Detects ontransitionend=
	}

	for _, pattern := range xssPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, fmt.Errorf("invalid regex pattern: %v", err)
		}
		if re.MatchString(input) {
			return true, nil
		}
	}

	return false, nil
}

func wsSQLInjectionDetection(input string) (bool, error) {

	// SQL injection detection patterns
	sqlPatterns := []string{
		`(?:select\s+.+\s+from\s+.+)`, // Detects select
		`(?:insert\s+.+\s+into\s+.+)`, // Detects insert
		`(?:update\s+.+\s+set\s+.+)`,  // Detects update
		`(?:delete\s+.+\s+from\s+.+)`, // Detects delete
		`(?:drop\s+.+)`,               // Detects drop
		`(?:truncate\s+.+)`,           // Detects truncate
		`(?:alter\s+.+)`,              // Detects alter
		`(?:exec\s+.+)`,               // Detects exec
		`(\s*(all|any|not|and|between|in|like|or|some|contains|containsall|containskey)\s+.+[\=\>\<=\!\~]+.+)`, // Detects logical operators
		`(?:let\s+.+[\=]\s+.*)`,                                 // Detects let
		`(?:begin\s*.+\s*end)`,                                  // Detects begin...end
		`(?:\s*[\/\*]+\s*.+\s*[\*\/]+)`,                         // Detects /* comments */
		`(?:\s*(\-\-)\s*.+\s+)`,                                 // Detects -- comments
		`(?:\s*(contains|containsall|containskey)\s+.+)`,        // Detects contains, containsall, containskey
		`\w*((%27)|('))((%6F)|o|(%4F))((%72)|r|(%52))`,          // Detects 'or'
		`exec(\s|\+)+(s|x)p\w+`,                                 // Detects exec sp_ and xp_
		`(?i)\b(select|insert|update|delete|drop|exec|union)\b`, // Detects SQL keywords
		`(?i)(\bor\b|\band\b).*(=|>|<|!=)`,                      // Detects logical operators combined with comparison operators
		`(?i)'\s*(or|and)\s*'\s*=\s*'`,                          // Detects patterns like ' or ''='
		`(?i)'\s*(or|and)\s*'[^=]*='`,                           // Detects patterns like ' or 'a'='a
		`(?i)'\s*(or|and)\s*1=1`,                                // Detects patterns like ' or 1=1

	}

	for _, pattern := range sqlPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, fmt.Errorf("invalid regex pattern: %v", err)
		}
		if re.MatchString(input) {
			return true, nil
		}
	}

	return false, nil
}

func wsHTTPVerbTamperingDetection(input string) (bool, error) {

	// HTTP verb tampering detection patterns
	httpVerbPatterns := []string{
		`(?i)(HEAD|OPTIONS|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)`, // Detects HTTP verbs
	}

	for _, pattern := range httpVerbPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, fmt.Errorf("invalid regex pattern: %v", err)
		}
		if re.MatchString(input) {
			return true, nil
		}
	}

	return false, nil
}

func wsLargeRequestDetection(input int) (bool, error) {
	// Large request detection patterns
	largeRequestPatterns := 5000 * 1024 // 5MB

	if input > largeRequestPatterns {
		return true, nil
	}

	return false, nil
}

func wsUnknowAttackDetection(input string) (bool, error) {
	return false, nil
}

// sendErrorResponse sends a JSON error response
func sendErrorResponse(w http.ResponseWriter, message string, errorCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errorCode)
	json.NewEncoder(w).Encode(shared.ErrorResponse{
		Status:    "error",
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
	if req.EventInfo == "" || req.AgentID == "" || req.AgentName == "" {
		sendErrorResponse(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if req.Payload.Data.ClientInformation.IP == "" || req.Payload.Data.HTTPRequest.Method == "" || req.Payload.Data.HTTPRequest.URL == "" || req.Payload.Data.HTTPRequest.Headers.UserAgent == "" || req.Payload.Data.HTTPRequest.Headers.ContentType == "" {
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

	status, agentProfile, err := processAgentProfile(req.AgentID, req.AgentName, "", req.EventInfo)
	if err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error processing Agent Configuration")
		http.Error(w, "Whale Sentinel - Internal Server Error", http.StatusInternalServerError)
		return
	}

	if status != "Success" {
		response := shared.ResponseBody{
			Status:             status,
			Message:            "Failed to retrieve profile",
			Data:               shared.ResponseData{},
			EventInfo:          eventInfo,
			RequestCreatedAt:   req.RequestCreatedAt,
			RequestProcessedAt: time.Now().Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

		log.Infof("POST %v - 200", r.URL)
		// Log the request to the logg collector
		go func(agentID string, agentName string, eventInfo string, rawRequest string) {
			// Log the request to the log collector
			logData := map[string]interface{}{
				"name":          "ws-common-attack-detection",
				"agent_id":      agentID,
				"agent_name":    agentName,
				"source":        strings.ToLower(serviceName),
				"destination":   "ws-common-attack-detection",
				"event_info":    eventInfo,
				"event_id":      eventID,
				"type":          "SERVICE_EVENT",
				"action":        "GET_PROFILE",
				"action_result": "GET_PROFILE_FAIL",
				"action_status": "FAILURE",
				"common_attack_detection": (map[string]bool{
					"cross_site_scripting": false,
					"sql_injection":        false,
					"http_verb_tampering":  false,
					"http_large_request":   false,
				}),
				"title":                "Received request from service",
				"request_created_at":   req.RequestCreatedAt,
				"request_processed_at": time.Now().Format(time.RFC3339),
				"raw_request":          rawRequest,
				"timestamp":            time.Now().Format(time.RFC3339),
			}

			logger.Log("info", "ws-common-attack-detection", logData)
		}(req.AgentID, req.AgentName, eventInfo, (req.Payload.Data.HTTPRequest.QueryParams + req.Payload.Data.HTTPRequest.Body))
		return
	}
	var agent shared.AgentProfileRaw

	err = json.Unmarshal([]byte(agentProfile), &agent)
	if err != nil {
		log.WithField("msg", err).Error("Failed to parse agent configuration from Redis / ws-configuration-service")
		http.Error(w, "Whale Sentinel - Internal Server Error", http.StatusInternalServerError)
		return
	}

	cad := agent.Profile["ws_module_common_attack_detection"].(map[string]interface{})

	// Process the rules
	var xssFound bool
	if cad["detect_cross_site_scripting"].(bool) {
		payload := req.Payload.Data.HTTPRequest.QueryParams + req.Payload.Data.HTTPRequest.Body
		decodedPayload, err := wsHandleDecoder(payload)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
		xssFound, err = wsCrossSiteScriptingDetection(decodedPayload)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
	}

	var sqlInjectionFound bool
	if cad["detect_sql_injection"].(bool) {
		payload := req.Payload.Data.HTTPRequest.QueryParams + req.Payload.Data.HTTPRequest.Body
		decodedPayload, err := wsHandleDecoder(payload)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
		sqlInjectionFound, err = wsSQLInjectionDetection(decodedPayload)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
	}

	var httpVerbTamperingFound bool
	if cad["detect_http_verb_tampering"].(bool) {
		httpVerbTamperingFound, err = wsHTTPVerbTamperingDetection(req.Payload.Data.HTTPRequest.Method)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
	}

	var httpLargeRequestFound bool
	if cad["detect_http_large_request"].(bool) {
		httpLargeRequestFound, err = wsLargeRequestDetection(req.Payload.Data.HTTPRequest.Headers.ContentLength)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
	}

	var unknowAttackFound bool
	if cad["detect_unknow_attack"].(bool) {
		payload := req.Payload.Data.HTTPRequest.QueryParams + req.Payload.Data.HTTPRequest.Body
		unknowAttackFound, err = wsUnknowAttackDetection(payload)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}

	}
	data := shared.ResponseData{
		CrossSiteScriptingDetection: xssFound,
		SQLInjectionDetection:       sqlInjectionFound,
		HTTPVerbTamperingDetection:  httpVerbTamperingFound,
		HTTPLargeRequestDetection:   httpLargeRequestFound,
		UnknowAttackDetection:       unknowAttackFound,
	}

	var analysisResult string
	if xssFound || sqlInjectionFound || httpVerbTamperingFound || httpLargeRequestFound || unknowAttackFound {
		analysisResult = "ABNORMAL_CLIENT_REQUEST"
	} else {
		analysisResult = "NORNAL_CLIENT_REQUEST"
	}

	response := shared.ResponseBody{
		Status:             "success",
		Message:            "Request processed successfully",
		Data:               data,
		EventInfo:          eventInfo,
		RequestCreatedAt:   req.RequestCreatedAt,
		RequestProcessedAt: time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Infof("POST %v - 200", r.URL)
	// Log the request to the logg collector
	go func(agentID string, agentName string, eventInfo string, rawRequest interface{}) {
		// Log the request to the log collector
		logData := map[string]interface{}{
			"name":          "ws-common-attack-detection",
			"agent_id":      agentID,
			"agent_name":    agentName,
			"source":        strings.ToLower(serviceName),
			"destination":   "ws-common-attack-detection",
			"event_info":    eventInfo,
			"event_id":      eventID,
			"type":          "SERVICE_EVENT",
			"action":        "ANALYSIS_REQUEST",
			"action_result": analysisResult,
			"action_status": "SUCCESSED",
			"common_attack_detection": (map[string]bool{
				"cross_site_scripting": xssFound,
				"sql_injection":        sqlInjectionFound,
				"http_verb_tampering":  httpVerbTamperingFound,
				"http_large_request":   httpLargeRequestFound,
				"unknow_attack":        unknowAttackFound,
			}),
			"title":                "Received request from service",
			"request_created_at":   req.RequestCreatedAt,
			"request_processed_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"raw_request":          rawRequest,
			"timestamp":            time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		}

		logger.Log("info", "ws-common-attack-detection", logData)
	}(req.AgentID, req.AgentName, eventInfo, (req))
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

func processAgentProfile(agentId string, agentName string, agentValue string, eventInfo string) (string, string, error) {
	getAgentProfile, err := handlerRedis(agentId, agentValue)
	if err != nil {
		log.Info("Cannot getting agent profile from Redis. Let getting agent profile from ws-configuration-service")
	}

	if getAgentProfile == "" {
		requestBody := map[string]interface{}{
			"event_info": eventInfo,
			"payload": map[string]interface{}{
				"data": map[string]interface{}{
					"type": "agent",
					"name": agentName,
					"id":   agentId,
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
	return "Success", getAgentProfile, nil
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
	timeoutHandler := http.TimeoutHandler(http.HandlerFunc(handleDetection), 30*time.Second, "Request timed out")

	// Register the timeout handler
	http.Handle("/api/v1/ws/services/common-attack-detection", apiKeyAuthMiddleware(timeoutHandler))
	log.Fatal(http.ListenAndServe(":5003", nil))
}
