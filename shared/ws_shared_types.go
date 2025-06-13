package shared

type (
	RequestBody struct {
		EventInfo        string  `json:"event_info"`
		AgentID          string  `json:"agent_id"`
		AgentName        string  `json:"agent_name"`
		Rules            Rules   `json:"rules"`
		Payload          Payload `json:"payload"`
		RequestCreatedAt string  `json:"request_created_at"`
	}

	Rules struct {
		DetectCrossSiteScripting bool `json:"detect_cross_site_scripting"`
		DetectLargeRequest       bool `json:"detect_large_request"`
		DetectSqlInjection       bool `json:"detect_sql_injection"`
		DetectHTTPVerbTampering  bool `json:"detect_http_verb_tampering"`
		DetectHTTPLargeRequest   bool `json:"detect_http_large_request"`
		DetectUnknowAttack       bool `json:"detect_unknow_attack"`
	}

	Payload struct {
		Data Data `json:"data"`
	}

	Data struct {
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
		Host        string            `json:"host"`
		Headers     HTTPRequestHeader `json:"headers"`
		QueryParams string            `json:"query_parameters"`
		Body        string            `json:"body"`
	}

	HTTPRequestHeader struct {
		UserAgent     string `json:"user-agent"`
		ContentType   string `json:"content-type"`
		ContentLength int    `json:"content-length"`
		Referer       string `json:"referer"`
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
		EventInfo          string       `json:"event_info"`
		RequestCreatedAt   string       `json:"request_created_at"`
		RequestProcessedAt string       `json:"request_processed_at"`
	}

	ResponseData struct {
		CrossSiteScriptingDetection bool `json:"cross_site_scripting_detection"`
		SQLInjectionDetection       bool `json:"sql_injection_detection"`
		HTTPVerbTamperingDetection  bool `json:"http_verb_tampering_detection"`
		HTTPLargeRequestDetection   bool `json:"http_large_request_detection"`
		UnknowAttackDetection       bool `json:"unknow_attack_detection"`
	}

	ErrorResponse struct {
		Status    string `json:"status"`
		Message   string `json:"message"`
		ErrorCode int    `json:"error_code"`
	}
)
