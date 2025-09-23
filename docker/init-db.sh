#!/bin/bash

# 数据库初始化脚本
echo "Initializing database..."

# 设置环境变量
export DATA_DIR=/app/data
export DATABASE_URL="sqlite:////app/data/webui.db"

# 确保数据目录存在并有正确权限
mkdir -p /app/data
chmod 755 /app/data

# 确保父目录可写
chown -R root:root /app/data

# 创建空的数据库文件如果不存在
if [ ! -f /app/data/webui.db ]; then
    echo "Creating empty database file..."
    touch /app/data/webui.db
    chmod 644 /app/data/webui.db
fi

# 测试SQLite是否可以访问该文件
if sqlite3 /app/data/webui.db "SELECT 1;" >/dev/null 2>&1; then
    echo "Database file is accessible."
else
    echo "Warning: Database file may not be accessible."
    ls -la /app/data/
    echo "Current working directory: $(pwd)"
    echo "DATABASE_URL: $DATABASE_URL"
    echo "DATA_DIR: $DATA_DIR"
fi

echo "Database initialization completed."

# 启动应用
exec "$@"