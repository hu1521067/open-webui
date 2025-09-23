# TC WebUI 离线部署指南

本文档描述如何在完全离线环境中部署TC WebUI，适用于使用本地Ollama和DeepSeek模型的场景。

## 快速启动

### 后端服务（推荐用于离线环境）

```bash
cd docker
docker-compose -f docker-compose.backend-only.yml up -d
```

### 完整服务（前端+后端）

```bash
cd docker
docker-compose up -d
```

## 离线配置说明

本配置已优化用于离线环境，包含以下设置：

### 核心离线设置
- `BYPASS_EMBEDDING_AND_RETRIEVAL=true` - 完全跳过嵌入模型初始化
- `RAG_EMBEDDING_MODEL_AUTO_UPDATE=false` - 禁用模型自动更新
- `HF_HUB_OFFLINE=1` - 强制Hugging Face Hub离线模式
- `TRANSFORMERS_OFFLINE=1` - 强制Transformers库离线模式
- `HF_HUB_DISABLE_TELEMETRY=1` - 禁用遥测数据发送
- `DISABLE_TELEMETRY=1` - 禁用所有遥测功能

### 数据库配置
- 使用SQLite本地数据库：`sqlite:////app/data/webui.db`
- 数据持久化存储在Docker卷中

### 本地Ollama集成
- 默认连接到：`http://host.docker.internal:11434`
- 可通过环境变量 `OLLAMA_BASE_URL` 自定义

## 环境变量配置

创建 `.env` 文件来自定义配置：

```bash
# Ollama服务地址
OLLAMA_BASE_URL=http://your-ollama-host:11434

# 用户管理
USER_LIMIT=50
ENABLE_SIGNUP=true
DEFAULT_USER_ROLE=pending

# 安全密钥
SECRET_KEY=your-secret-key-here

# 离线模式（已默认启用）
BYPASS_EMBEDDING_AND_RETRIEVAL=true
HF_HUB_OFFLINE=1
TRANSFORMERS_OFFLINE=1

# SSO配置（可选）
ENABLE_OAUTH_SIGNUP=false
OAUTH_CLIENT_ID=
OAUTH_CLIENT_SECRET=
OPENID_PROVIDER_URL=
```

## 服务端点

启动后可访问以下端点：

- **健康检查**: `http://localhost:8080/health`
- **API配置**: `http://localhost:8080/api/config`
- **API版本**: `http://localhost:8080/api/version`
- **Web界面**: `http://localhost:3000` （仅完整部署）

## 验证部署

```bash
# 检查服务状态
docker-compose -f docker-compose.backend-only.yml ps

# 检查健康状态
curl http://localhost:8080/health

# 查看日志
docker-compose -f docker-compose.backend-only.yml logs backend
```

## 常见问题

### Q: 看到嵌入模型相关警告？
A: 这是正常的，因为我们在离线模式下跳过了嵌入模型初始化。这些警告不影响核心功能。

### Q: 如何连接到本地Ollama？
A: 确保Ollama在主机上运行，默认配置会自动连接到 `host.docker.internal:11434`。

### Q: 数据存储在哪里？
A: 所有数据存储在Docker卷 `tc_webui_data` 中，可以安全地重启容器而不丢失数据。

### Q: 如何更新配置？
A: 修改环境变量后，重启容器：
```bash
docker-compose -f docker-compose.backend-only.yml down
docker-compose -f docker-compose.backend-only.yml up -d
```

## 生产环境建议

1. 设置强密码的 `SECRET_KEY`
2. 配置适当的 `CORS_ALLOW_ORIGIN` 替代 `*`
3. 使用外部Redis服务提高性能（可选）
4. 定期备份 `tc_webui_data` 卷中的数据
5. 监控容器健康状态

## 故障排除

如果遇到问题，请检查：

1. 容器日志：`docker-compose logs backend`
2. 健康检查：`curl http://localhost:8080/health`
3. 端口占用：确保8080端口未被占用
4. Ollama连接：确保Ollama服务可访问

本配置已经过完整测试，适用于离线环境中的生产部署。