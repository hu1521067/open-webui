# TC WebUI Docker 部署

本目录包含 TC WebUI 的 Docker 部署配置文件。

## 文件说明

### 部署配置
- `docker-compose.yml` - 完整部署（前端 + 后端）
- `docker-compose.backend-only.yml` - 仅后端部署（推荐离线环境）
- `docker-compose.external.yml` - 外部数据库和Redis部署

### Docker 镜像
- `Dockerfile.backend` - 后端镜像构建文件
- `Dockerfile.frontend` - 前端镜像构建文件

### 配置文件
- `.env.offline.example` - 离线环境配置模板
- `.env.external.example` - 外部数据库和Redis配置模板
- `nginx.conf` - Nginx 反向代理配置
- `init-db.sh` - 数据库初始化脚本

### 文档
- `OFFLINE_DEPLOYMENT.md` - 离线部署详细指南

## 快速开始

### 离线环境（推荐）
```bash
# 复制环境配置
cp .env.offline.example .env

# 启动后端服务
docker-compose -f docker-compose.backend-only.yml up -d
```

### 完整部署
```bash
# 启动前端 + 后端
docker-compose up -d
```

### 外部数据库和Redis
```bash
# 复制外部配置模板
cp .env.external.example .env

# 修改数据库和Redis连接信息
# 启动服务
docker-compose -f docker-compose.external.yml up -d
```

## 服务端点
- 后端 API: http://localhost:8080
- 前端界面: http://localhost:3000 （仅完整部署）
- 健康检查: http://localhost:8080/health

详细部署说明请参考 `OFFLINE_DEPLOYMENT.md`。