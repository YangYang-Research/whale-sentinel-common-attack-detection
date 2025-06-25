package shared

type (
	RequestBody struct {
		EventInfo        string  `json:"event_info"`
		Payload          Payload `json:"payload"`
		RequestCreatedAt string  `json:"request_created_at"`
	}

	Payload struct {
		Data Data `json:"data"`
	}

	Data struct {
		AgentID           string            `json:"agent_id"`
		AgentName         string            `json:"agent_name"`
		ClientInformation ClientInformation `json:"client_information"`
		HTTPRequest       HTTPRequest       `json:"http_request"`
	}

	ClientInformation struct {
		IP             string `json:"ip"`
		DeviceType     string `json:"device_type"`
		NetworkType    string `json:"network_type"`
		Platform       string `json:"platform"`
		Browser        string `json:"browser"`
		BrowserVersion string `json:"browser_version"`
	}

	HTTPRequest struct {
		Method      string            `json:"method"`
		URL         string            `json:"url"`
		Scheme      string            `json:"scheme"`
		Host        string            `json:"host"`
		Endpoint    string            `json:"endpoint"`
		Headers     HTTPRequestHeader `json:"headers"`
		QueryParams string            `json:"query_parameters"`
		Body        string            `json:"body"`
		Files       []UploadedFile    `json:"files"`
	}

	HTTPRequestHeader struct {
		UserAgent     string `json:"user-agent"`
		ContentType   string `json:"content-type"`
		ContentLength int    `json:"content-length"`
		Referer       string `json:"referer"`
	}

	UploadedFile struct {
		FileName    string `json:"file_name"`
		FileSize    int    `json:"file_size"`
		FileContent string `json:"file_content"`
		FileType    string `json:"file_type"`
		FileHash256 string `json:"file_hash256"`
	}

	AgentProfileRaw struct {
		Profile map[string]interface{} `json:"profile"`
	}

	ServiceProfileRaw struct {
		Profile map[string]interface{} `json:"profile"`
	}

	ResponseBody struct {
		Status             string       `json:"status"`
		Message            string       `json:"message"`
		Data               ResponseData `json:"data"`
		AnalysisResult     string       `json:"analysis_result"`
		EventInfo          string       `json:"event_info"`
		RequestCreatedAt   string       `json:"request_created_at"`
		RequestProcessedAt string       `json:"request_processed_at"`
	}

	ResponseData struct {
		CrossSiteScriptingDetection bool `json:"cross_site_scripting_detection"`
		SQLInjectionDetection       bool `json:"sql_injection_detection"`
		HTTPVerbTamperingDetection  bool `json:"http_verb_tampering_detection"`
		HTTPLargeRequestDetection   bool `json:"http_large_request_detection"`
		UnknownAttackDetection      bool `json:"unknown_attack_detection"`
		InsecureFileUploadDetection bool `json:"insecure_file_upload_detection"`
		InsecureRedirectDetection   bool `json:"insecure_redirect_detection"`
	}

	ErrorResponse struct {
		Status    string `json:"status"`
		Message   string `json:"message"`
		ErrorCode int    `json:"error_code"`
	}
)
