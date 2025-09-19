#!/usr/bin/env python3
"""
SSO连接测试脚本
用于测试统一身份认证服务器的连接和配置
"""
import asyncio
import aiohttp
import os
import sys

# SSO配置
SSO_SERVER_URL = os.environ.get("SSO_SERVER_URL", "http://10.0.0.1:9700")
SSO_CLIENT_ID = os.environ.get("SSO_CLIENT_ID", "tc-ai")
SSO_CLIENT_SECRET = os.environ.get("SSO_CLIENT_SECRET", "5#Z5aJVgmzWLXWw*")

async def test_sso_connection():
    """测试SSO服务器连接"""
    print("=== SSO连接测试 ===")
    print(f"服务器地址: {SSO_SERVER_URL}")
    print(f"客户端ID: {SSO_CLIENT_ID}")
    print(f"客户端密钥: {'***' if SSO_CLIENT_SECRET else 'None'}")
    print()

    if not all([SSO_SERVER_URL, SSO_CLIENT_ID, SSO_CLIENT_SECRET]):
        print("❌ 错误: SSO配置不完整")
        return False

    # 测试1: 基础连接测试
    print("1. 测试基础连接...")
    try:
        async with aiohttp.ClientSession() as session:
            test_url = f"{SSO_SERVER_URL}/api-auth/oauth/token"
            async with session.get(SSO_SERVER_URL, timeout=5) as response:
                print(f"   ✅ 服务器可访问 (HTTP {response.status})")
    except Exception as e:
        print(f"   ❌ 服务器连接失败: {e}")
        return False

    # 测试2: 客户端认证测试
    print("2. 测试客户端认证...")
    try:
        token_url = f"{SSO_SERVER_URL}/api-auth/oauth/token"
        token_data = {
            "client_id": SSO_CLIENT_ID,
            "client_secret": SSO_CLIENT_SECRET,
            "grant_type": "client_credentials"
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(token_url, data=token_data, timeout=10) as response:
                if response.status == 200:
                    result = await response.json()
                    print(f"   ✅ 客户端认证成功")
                    print(f"   令牌类型: {result.get('token_type', 'unknown')}")
                    print(f"   过期时间: {result.get('expires_in', 'unknown')}秒")
                    return True
                else:
                    error_text = await response.text()
                    print(f"   ❌ 客户端认证失败 (HTTP {response.status})")
                    print(f"   错误信息: {error_text}")
                    return False

    except Exception as e:
        print(f"   ❌ 客户端认证测试失败: {e}")
        return False

async def test_authorization_flow():
    """测试授权码流程（模拟）"""
    print("\n=== OAuth授权码流程测试 ===")

    # 生成授权URL
    base_url = "http://localhost:8080"  # 假设本地服务运行在8080端口
    redirect_uri = f"{base_url}/api/v1/auths/unified_oauth/redirect"

    auth_url = (
        f"{SSO_SERVER_URL}/api-auth/oauth/authorize"
        f"?response_type=code"
        f"&client_id={SSO_CLIENT_ID}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=all"
        f"&state=test123"
    )

    print(f"授权URL: {auth_url}")
    print()
    print("要测试完整的OAuth流程，请:")
    print("1. 启动TC WebUI服务 (./dev.sh)")
    print("2. 在浏览器中访问上述授权URL")
    print("3. 完成SSO登录授权")
    print("4. 观察控制台日志输出")

def print_debug_info():
    """打印调试信息"""
    print("\n=== 调试信息 ===")
    print("如果遇到问题，请检查:")
    print("1. SSO服务器是否正常运行")
    print("2. 网络连接是否正常")
    print("3. 客户端ID和密钥是否正确")
    print("4. 重定向URI是否在SSO系统中正确配置")
    print()
    print("环境变量设置:")
    print(f"export SSO_SERVER_URL={SSO_SERVER_URL}")
    print(f"export SSO_CLIENT_ID={SSO_CLIENT_ID}")
    print(f"export SSO_CLIENT_SECRET={SSO_CLIENT_SECRET}")
    print()
    print("启动开发服务器:")
    print("cd backend && ./dev.sh")

async def main():
    """主函数"""
    success = await test_sso_connection()

    if success:
        await test_authorization_flow()

    print_debug_info()

    return success

if __name__ == "__main__":
    try:
        result = asyncio.run(main())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\n测试被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n测试过程中发生错误: {e}")
        sys.exit(1)