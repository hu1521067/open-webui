export CORS_ALLOW_ORIGIN="http://localhost:5173"

# 启用统一身份认证
export ENABLE_UNIFIED_SSO=true
# 统一身份认证服务器地址
export SSO_SERVER_URL=http://10.0.0.1:9700
# OAuth 2.0 客户端ID（由认证端提供）
export SSO_CLIENT_ID=tc-ai
# OAuth 2.0 客户端密钥（由认证端提供）
export SSO_CLIENT_SECRET="5#Z5aJVgmzWLXWw*"

# 启用详细日志调试
export GLOBAL_LOG_LEVEL=DEBUG
export SRC_LOG_LEVELS__MAIN=DEBUG
export SRC_LOG_LEVELS__OAUTH=DEBUG

PORT="${PORT:-8080}"
echo "启动TC WebUI开发服务器..."
echo "SSO服务器地址: $SSO_SERVER_URL"
echo "客户端ID: $SSO_CLIENT_ID"
echo "日志级别: DEBUG"
echo "监听端口: $PORT"
echo "--------------------------------"

uvicorn tc_webui.main:app --port "$PORT" --host 0.0.0.0 --forwarded-allow-ips '*' --reload --log-level debug
