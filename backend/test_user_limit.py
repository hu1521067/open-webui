#!/usr/bin/env python3
"""
用户数量限制功能测试脚本
"""
import asyncio
import aiohttp
import json
import sys
import os

# 添加项目路径到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tc_webui.models.users import Users
from tc_webui.models.auths import Auths
from tc_webui.utils.auth import get_password_hash
import uuid
import time

def test_user_limit_functions():
    """测试用户限制相关的数据库函数"""
    print("=== 用户数量限制功能测试 ===\n")

    # 1. 测试获取用户统计
    print("1. 测试用户统计功能...")
    try:
        total_users = Users.get_num_users()
        admin_users = Users.get_admin_users_count()
        non_admin_users = Users.get_non_admin_users_count()

        print(f"   总用户数: {total_users}")
        print(f"   管理员用户数: {admin_users}")
        print(f"   普通用户数: {non_admin_users}")
        print("   ✅ 用户统计功能正常\n")
    except Exception as e:
        print(f"   ❌ 用户统计功能失败: {e}\n")
        return False

    # 2. 测试获取最久未登录用户
    print("2. 测试获取最久未登录用户...")
    try:
        oldest_user = Users.get_oldest_inactive_non_admin_user()
        if oldest_user:
            print(f"   最久未登录用户: {oldest_user.name} ({oldest_user.email})")
            print(f"   最后活跃时间: {oldest_user.last_active_at}")
            print(f"   角色: {oldest_user.role}")
        else:
            print("   没有找到非管理员用户")
        print("   ✅ 获取最久未登录用户功能正常\n")
    except Exception as e:
        print(f"   ❌ 获取最久未登录用户功能失败: {e}\n")

    # 3. 测试用户限制执行（仅在用户数超过限制时）
    print("3. 测试用户限制执行...")
    try:
        result = Users.enforce_user_limit(50)
        print(f"   当前用户数: {result['current_count']}")
        print(f"   最大用户数: {result['max_users']}")

        if result['users_removed']:
            print(f"   删除用户数: {len(result['users_removed'])}")
            for user in result['users_removed']:
                print(f"     - {user['name']} ({user['email']})")
        else:
            print("   无需删除用户")

        if result['warnings']:
            for warning in result['warnings']:
                print(f"   警告: {warning}")

        print(f"   最终用户数: {result.get('final_count', result['current_count'])}")
        print("   ✅ 用户限制执行功能正常\n")
    except Exception as e:
        print(f"   ❌ 用户限制执行功能失败: {e}\n")

    return True

async def test_api_endpoints():
    """测试用户管理API端点"""
    print("=== API端点测试 ===\n")

    base_url = "http://localhost:8080"

    # 注意：这需要管理员token，实际测试时需要替换
    admin_token = "YOUR_ADMIN_TOKEN_HERE"

    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }

    try:
        async with aiohttp.ClientSession() as session:
            # 测试用户统计API
            print("1. 测试用户统计API...")
            async with session.get(f"{base_url}/api/v1/auths/admin/users/stats", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"   总用户数: {data['total_users']}")
                    print(f"   管理员数: {data['admin_users']}")
                    print(f"   剩余名额: {data['remaining_slots']}")
                    print(f"   是否警告: {data['warning']}")
                    print("   ✅ 用户统计API正常")
                else:
                    print(f"   ❌ 用户统计API失败: HTTP {response.status}")

            print()

            # 测试手动执行用户限制API
            print("2. 测试手动执行用户限制API...")
            async with session.post(f"{base_url}/api/v1/auths/admin/users/enforce_limit", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"   执行结果: {data['message']}")
                    if data['details']['users_removed']:
                        print(f"   删除用户数: {len(data['details']['users_removed'])}")
                    print("   ✅ 手动执行用户限制API正常")
                else:
                    print(f"   ❌ 手动执行用户限制API失败: HTTP {response.status}")

    except Exception as e:
        print(f"   ❌ API测试失败: {e}")
        print("   提示: 请确保服务正在运行且提供了有效的管理员token")

def simulate_user_creation():
    """模拟用户创建以测试限制功能"""
    print("=== 模拟用户创建测试 ===\n")

    current_count = Users.get_num_users()
    print(f"当前用户数: {current_count}")

    # 如果用户数少于48，创建一些测试用户
    if current_count < 48:
        print("用户数较少，跳过模拟测试")
        print("提示: 当用户数接近50时，可以观察自动删除功能")
        return

    print("用户数接近限制，可以测试自动删除功能")
    print("建议通过SSO登录或注册新用户来触发自动删除机制")

def main():
    """主测试函数"""
    print("开始用户数量限制功能测试...\n")

    # 测试数据库函数
    if not test_user_limit_functions():
        print("❌ 数据库函数测试失败，退出")
        return

    # 模拟用户创建测试
    simulate_user_creation()

    print("\n=== 测试完成 ===")
    print("如需测试API端点，请：")
    print("1. 确保服务正在运行 (./dev.sh)")
    print("2. 获取管理员token")
    print("3. 修改脚本中的 admin_token 变量")
    print("4. 运行: python3 test_user_limit.py --api")

if __name__ == "__main__":
    if "--api" in sys.argv:
        asyncio.run(test_api_endpoints())
    else:
        main()