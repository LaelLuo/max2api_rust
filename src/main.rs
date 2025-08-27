use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::Response,
    routing::post,
    Router,
};
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info};
use uuid::Uuid;

// 配置结构
#[derive(Debug, Clone)]
struct Config {
    port: u16,
    target_api_url: String,
    log_level: String,
    default_api_key: String,
    default_user_id: String,
    force_default_api_key: bool,
}

impl Config {
    fn from_env() -> Self {
        Self {
            port: env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .unwrap_or(3000),
            target_api_url: env::var("TARGET_API_URL")
                .unwrap_or_else(|_| "https://api.packycode.com/v1/messages?beta=true".to_string()),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            default_api_key: env::var("DEFAULT_API_KEY").unwrap_or_default(),
            default_user_id: env::var("DEFAULT_USER_ID").unwrap_or_default(),
            force_default_api_key: env::var("FORCE_DEFAULT_API_KEY")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
        }
    }
}

// 应用状态
#[derive(Clone)]
struct AppState {
    config: Config,
    client: Client,
}

// 系统消息结构
#[derive(Debug, Serialize, Deserialize, Clone)]
struct SystemMessage {
    text: String,
    #[serde(rename = "type")]
    message_type: String,
}

// 元数据结构
#[derive(Debug, Serialize, Deserialize)]
struct Metadata {
    user_id: String,
}

// 日志记录器
struct Logger {
    level: String,
}

impl Logger {
    fn new(level: String) -> Self {
        Self { level }
    }

    fn info(&self, message: &str) {
        if self.level == "info" || self.level == "debug" {
            info!("[INFO] {} - {}", Utc::now().to_rfc3339(), message);
        }
    }

    fn debug(&self, message: &str) {
        if self.level == "debug" {
            debug!("[DEBUG] {} - {}", Utc::now().to_rfc3339(), message);
        }
    }

    fn error(&self, message: &str) {
        error!("[ERROR] {} - {}", Utc::now().to_rfc3339(), message);
    }
}

// 提取API Key的函数
fn extract_api_key(headers: &HeaderMap, config: &Config, logger: &Logger) -> Option<String> {
    // 如果强制使用默认API key，直接返回默认key（如果配置了的话）
    if config.force_default_api_key {
        if !config.default_api_key.is_empty() {
            logger.debug("Force using default API key from configuration (ignoring auth headers)");
            return Some(config.default_api_key.clone());
        } else {
            logger.debug("FORCE_DEFAULT_API_KEY is enabled but DEFAULT_API_KEY is not configured");
            return None;
        }
    }

    // 尝试从authorization或x-api-key头部获取
    let auth_header = headers
        .get("authorization")
        .or_else(|| headers.get("x-api-key"))
        .and_then(|h| h.to_str().ok());

    if let Some(auth_value) = auth_header {
        // 如果是Bearer token格式
        if auth_value.starts_with("Bearer ") {
            let api_key = auth_value[7..].to_string();
            logger.debug(&format!(
                "Extracted API key from Bearer token: {}...",
                &api_key[..api_key.len().min(10)]
            ));
            return Some(api_key);
        }
        // 直接返回API key
        logger.debug(&format!(
            "Extracted API key directly: {}...",
            &auth_value[..auth_value.len().min(10)]
        ));
        return Some(auth_value.to_string());
    }

    // 如果请求头中没有API key，尝试使用配置中的默认key
    if !config.default_api_key.is_empty() {
        logger.debug("Using default API key from configuration");
        return Some(config.default_api_key.clone());
    }

    None
}

// 生成UUID v4
fn generate_uuid() -> String {
    Uuid::new_v4().to_string()
}

// 生成格式化的用户ID
fn generate_formatted_user_id(config: &Config) -> String {
    if config.default_user_id.is_empty() {
        return String::new();
    }
    let session_uuid = generate_uuid();
    format!("user_{}_account__session_{}", config.default_user_id, session_uuid)
}

// 检查是否为Claude 3.5 Haiku模型
fn is_claude_haiku_model(model: &str) -> bool {
    model.contains("claude-3-5-haiku")
}

// 转换请求头的函数 - 根据模型类型和流式设置选择不同的转换策略
fn transform_headers(
    original_headers: &HeaderMap,
    api_key: &str,
    model: Option<&str>,
    is_stream: bool,
    logger: &Logger,
) -> HeaderMap {
    let mut headers = HeaderMap::new();

    // 基础头部
    headers.insert("user-agent", "claude-cli/1.0.86 (external, cli)".parse().unwrap());
    headers.insert("accept", "application/json".parse().unwrap());
    headers.insert("accept-encoding", "gzip, deflate, br, zstd".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert("anthropic-dangerous-direct-browser-access", "true".parse().unwrap());

    // anthropic-version
    let anthropic_version = original_headers
        .get("anthropic-version")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("2023-06-01");
    headers.insert("anthropic-version", anthropic_version.parse().unwrap());

    // authorization
    headers.insert("authorization", format!("Bearer {}", api_key).parse().unwrap());

    // 其他固定头部
    headers.insert("x-app", "cli".parse().unwrap());
    headers.insert("x-stainless-arch", "x64".parse().unwrap());
    headers.insert("x-stainless-lang", "js".parse().unwrap());
    headers.insert("x-stainless-os", "Windows".parse().unwrap());
    headers.insert("x-stainless-package-version", "0.55.1".parse().unwrap());
    headers.insert("x-stainless-retry-count", "0".parse().unwrap());
    headers.insert("x-stainless-runtime", "node".parse().unwrap());
    headers.insert("x-stainless-runtime-version", "v24.3.0".parse().unwrap());
    headers.insert("x-stainless-timeout", "60".parse().unwrap());

    // 只有在流式请求时才添加 x-stainless-helper-method
    if is_stream {
        headers.insert("x-stainless-helper-method", "stream".parse().unwrap());
        logger.debug("Adding stream helper method header");
    }

    // 根据模型类型设置不同的anthropic-beta头部
    if let Some(model_name) = model {
        if is_claude_haiku_model(model_name) {
            headers.insert("anthropic-beta", "fine-grained-tool-streaming-2025-05-14".parse().unwrap());
            logger.debug(&format!("Using Claude 3.5 Haiku headers for model: {}", model_name));
        } else {
            headers.insert("anthropic-beta", "claude-code-20250219,context-1m-2025-08-07,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14".parse().unwrap());
            logger.debug(&format!("Using enhanced headers for model: {}", model_name));
        }
    } else {
        headers.insert("anthropic-beta", "claude-code-20250219,context-1m-2025-08-07,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14".parse().unwrap());
        logger.debug("Using enhanced headers for model: unknown");
    }

    headers
}

// 预定义的系统消息 - 在每个请求的system数组第一个位置添加
fn get_cc_system_message() -> SystemMessage {
    SystemMessage {
        text: "You are Claude Code, Anthropic's official CLI for Claude.".to_string(),
        message_type: "text".to_string(),
    }
}

// 检查system数组中是否已经存在相同的系统消息
fn has_cc_system_message(system_array: &[Value]) -> bool {
    let cc_message = get_cc_system_message();
    system_array.iter().any(|msg| {
        if let Some(obj) = msg.as_object() {
            obj.get("text").and_then(|t| t.as_str()) == Some(&cc_message.text)
                && obj.get("type").and_then(|t| t.as_str()) == Some(&cc_message.message_type)
        } else {
            false
        }
    })
}

// 修改请求体，添加metadata和cc系统消息
fn modify_request_body(
    body: &str,
    config: &Config,
    logger: &Logger,
) -> Result<(String, Option<String>, bool), Box<dyn std::error::Error>> {
    let mut request_data: Value = serde_json::from_str(body)?;

    // 获取模型和流式设置信息
    let model = request_data.get("model").and_then(|m| m.as_str()).map(|s| s.to_string());
    let is_stream = request_data.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);

    // 添加metadata字段
    if request_data.get("metadata").is_none() {
        let formatted_user_id = generate_formatted_user_id(config);
        let metadata = json!({
            "user_id": formatted_user_id
        });
        request_data["metadata"] = metadata;
        logger.debug(&format!(
            "Added metadata to request body with user_id: {}...",
            &formatted_user_id[..formatted_user_id.len().min(50)]
        ));
    }

    // 处理system字段
    let cc_message = get_cc_system_message();
    let cc_message_value = serde_json::to_value(&cc_message)?;

    if let Some(system) = request_data.get_mut("system") {
        match system {
            Value::Array(arr) => {
                // 如果system是数组，检查是否已存在cc系统消息
                if !has_cc_system_message(arr) {
                    arr.insert(0, cc_message_value);
                    logger.debug("Added cc system message to system array at index 0");
                } else {
                    logger.debug("cc system message already exists in system array, skipping");
                }
            }
            Value::String(s) => {
                // 如果system是字符串，转换为数组并添加cc系统消息
                let original_system_message = json!({
                    "text": s,
                    "type": "text"
                });
                *system = json!([cc_message_value, original_system_message]);
                logger.debug("Converted system string to array and added cc system message at index 0");
            }
            _ => {
                // 其他情况，创建新的数组
                *system = json!([cc_message_value]);
                logger.debug("Created new system array with cc system message");
            }
        }
    } else {
        // 如果没有system字段，创建一个包含cc系统消息的数组
        request_data["system"] = json!([cc_message_value]);
        logger.debug("Created new system array with cc system message");
    }

    let modified_body = serde_json::to_string(&request_data)?;
    logger.info(&format!(
        "Detected model: {}, stream: {}",
        model.as_deref().unwrap_or("not specified"),
        is_stream
    ));

    Ok((modified_body, model, is_stream))
}

// 代理请求到Packycode API
async fn proxy_request(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, StatusCode> {
    let logger = Logger::new(state.config.log_level.clone());

    // 只处理 /v1/messages 路径
    let uri = request.uri();
    if uri.path() != "/v1/messages" {
        logger.debug(&format!("Unsupported path: {}", uri.path()));
        return Err(StatusCode::NOT_FOUND);
    }

    // 提取原始请求头
    let original_headers = request.headers().clone();

    logger.debug("=== INCOMING REQUEST DEBUG ===");
    logger.debug(&format!("Request URL: {}", uri));
    logger.debug(&format!("Request Method: {}", request.method()));
    logger.debug(&format!("Original request headers: {:#?}", original_headers));

    // 提取API Key
    let api_key = match extract_api_key(&original_headers, &state.config, &logger) {
        Some(key) => key,
        None => {
            logger.error("Missing API Key in request");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // 读取请求体
    let body_bytes = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => {
            logger.error("Failed to read request body");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let body = String::from_utf8_lossy(&body_bytes);
    logger.debug(&format!("Request body length: {} characters", body.len()));
    logger.debug(&format!("Original request body: {}", body));

    // 解析请求体以获取模型和流式设置信息，并添加metadata和cc系统消息
    let (modified_body, model, is_stream) = match modify_request_body(&body, &state.config, &logger) {
        Ok(result) => result,
        Err(e) => {
            logger.error(&format!("Failed to parse request body JSON: {}", e));
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    logger.debug(&format!("Modified request body: {}", modified_body));

    // 转换请求头 - 传入模型和流式信息
    let transformed_headers = transform_headers(
        &original_headers,
        &api_key,
        model.as_deref(),
        is_stream,
        &logger,
    );

    // 使用配置中的目标URL
    let target_url = &state.config.target_api_url;
    logger.info(&format!("Proxying request to: {}", target_url));

    logger.debug("=== OUTGOING REQUEST DEBUG ===");
    logger.debug(&format!("Target URL: {}", target_url));
    logger.debug(&format!("Transformed headers: {:#?}", transformed_headers));

    // 发送请求到Packycode API
    let mut req_builder = state.client.post(target_url);

    // 添加转换后的头部
    for (key, value) in transformed_headers.iter() {
        if let Ok(value_str) = value.to_str() {
            req_builder = req_builder.header(key.as_str(), value_str);
        }
    }

    let response = match req_builder.body(modified_body).send().await {
        Ok(resp) => resp,
        Err(e) => {
            logger.error(&format!("Proxy error: {}", e));
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    logger.info(&format!("Response status: {}", response.status()));
    logger.debug("=== INCOMING RESPONSE DEBUG ===");
    logger.debug(&format!("Response status: {}", response.status()));

    // 记录响应头
    logger.debug(&format!("Response headers: {:#?}", response.headers()));

    // 创建响应头，保持原始响应的内容类型和其他重要头部
    let mut response_headers = HeaderMap::new();
    for (key, value) in response.headers().iter() {
        if let Ok(value_str) = value.to_str() {
            if let (Ok(axum_key), Ok(axum_value)) = (
                axum::http::HeaderName::from_bytes(key.as_str().as_bytes()),
                axum::http::HeaderValue::from_str(value_str)
            ) {
                response_headers.insert(axum_key, axum_value);
            }
        }
    }

    let status_code = response.status().as_u16();
    let axum_status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    // 检查是否是流式响应
    let content_type = response.headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if content_type.contains("text/stream") || content_type.contains("text/event-stream") {
        logger.debug("Returning streaming response (body not logged for streams)");
        logger.debug("=== OUTGOING RESPONSE DEBUG ===");
        logger.debug("Response type: Streaming");
        logger.debug(&format!("Final response headers: {:#?}", response_headers));

        let stream = response.bytes_stream();
        let body = axum::body::Body::from_stream(stream);

        let mut resp = Response::new(body);
        *resp.status_mut() = axum_status;
        *resp.headers_mut() = response_headers;

        return Ok(resp);
    }

    // 对于非流式响应，读取完整内容
    let response_body = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            logger.error(&format!("Failed to read response body: {}", e));
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    logger.debug(&format!("Response body length: {} characters", response_body.len()));
    logger.debug("=== OUTGOING RESPONSE DEBUG ===");
    logger.debug("Response type: Non-streaming");
    logger.debug(&format!("Final response headers: {:#?}", response_headers));
    logger.debug(&format!("Final response body: {}", response_body));

    let mut resp = Response::new(response_body.into());
    *resp.status_mut() = axum_status;
    *resp.headers_mut() = response_headers;

    Ok(resp)
}

// 处理OPTIONS请求（CORS预检）
async fn handle_options() -> Result<Response, StatusCode> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body("".into())
        .unwrap())
}

// 错误处理中间件
async fn handle_method_not_allowed() -> Result<Response, StatusCode> {
    Err(StatusCode::METHOD_NOT_ALLOWED)
}

#[tokio::main]
async fn main() {
    // 加载 .env 文件（如果存在）
    dotenv::dotenv().ok();

    // 从环境变量加载配置
    let config = Config::from_env();

    // 根据配置初始化日志级别
    let log_level = match config.log_level.as_str() {
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .init();

    info!("=== MAX2API RUST SERVER STARTING ===");
    info!("Port: {}", config.port);
    info!("Target API URL: {}", config.target_api_url);
    info!("Log Level: {}", config.log_level);
    info!("Force Default API Key: {}", config.force_default_api_key);

    // 创建HTTP客户端
    let client = Client::new();

    // 创建应用状态
    let state = AppState {
        config: config.clone(),
        client,
    };

    // 创建日志记录器
    let logger = Logger::new(config.log_level.clone());

    // 创建CORS层
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);

    // 创建路由
    let app = Router::new()
        .route("/v1/messages", post(proxy_request))
        .route("/v1/messages", axum::routing::options(handle_options))
        .fallback(handle_method_not_allowed)
        .layer(cors)
        .with_state(state);

    // 启动服务器
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.port))
        .await
        .expect("Failed to bind to address");

    logger.info(&format!("🚀 Server running on http://localhost:{}", config.port));
    logger.info(&format!("📡 Proxying Anthropic API requests to: {}", config.target_api_url));
    logger.info("📋 Endpoint: POST /v1/messages");
    logger.info(&format!("🔧 Log level: {}", config.log_level));
    logger.info(&format!(
        "🔑 Default API key: {}",
        if config.default_api_key.is_empty() { "not set" } else { "configured" }
    ));
    logger.info(&format!(
        "🔒 Force default API key: {}",
        if config.force_default_api_key { "enabled" } else { "disabled" }
    ));
    logger.info(&format!(
        "👤 Default user ID: {}",
        if config.default_user_id.is_empty() {
            "not set".to_string()
        } else {
            format!("{} (will be formatted as user_{}_account__session_{{uuid}})",
                   config.default_user_id, config.default_user_id)
        }
    ));

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}
