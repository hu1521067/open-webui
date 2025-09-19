import re
import uuid
import time
import datetime
import logging
import os
from aiohttp import ClientSession

from tc_webui.models.auths import (
    AddUserForm,
    ApiKey,
    Auths,
    Token,
    LdapForm,
    SigninForm,
    SigninResponse,
    SignupForm,
    UpdatePasswordForm,
    UserResponse,
)
from tc_webui.models.users import Users, UpdateProfileForm
from tc_webui.models.groups import Groups
from tc_webui.models.oauth_sessions import OAuthSessions

from tc_webui.constants import ERROR_MESSAGES, WEBHOOK_MESSAGES
from tc_webui.env import (
    WEBUI_AUTH,
    WEBUI_AUTH_TRUSTED_EMAIL_HEADER,
    WEBUI_AUTH_TRUSTED_NAME_HEADER,
    WEBUI_AUTH_TRUSTED_GROUPS_HEADER,
    WEBUI_AUTH_COOKIE_SAME_SITE,
    WEBUI_AUTH_COOKIE_SECURE,
    WEBUI_AUTH_SIGNOUT_REDIRECT_URL,
    ENABLE_INITIAL_ADMIN_SIGNUP,
    SRC_LOG_LEVELS,
)
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response, JSONResponse
from tc_webui.config import (
    OPENID_PROVIDER_URL,
    ENABLE_OAUTH_SIGNUP,
    ENABLE_LDAP,
    SSO_SERVER_URL,
    SSO_CLIENT_ID,
    SSO_CLIENT_SECRET,
    ENABLE_UNIFIED_SSO
)
import aiohttp
from pydantic import BaseModel

from tc_webui.utils.misc import parse_duration, validate_email_format
from tc_webui.utils.auth import (
    decode_token,
    create_api_key,
    create_token,
    get_admin_user,
    get_verified_user,
    get_current_user,
    get_password_hash,
    get_http_authorization_cred,
)
from tc_webui.utils.webhook import post_webhook
from tc_webui.utils.access_control import get_permissions

from typing import Optional, List

from ssl import CERT_NONE, CERT_REQUIRED, PROTOCOL_TLS

from ldap3 import Server, Connection, NONE, Tls
from ldap3.utils.conv import escape_filter_chars

router = APIRouter()

log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["MAIN"])

############################
# GetSessionUser
############################


class SessionUserResponse(Token, UserResponse):
    expires_at: Optional[int] = None
    permissions: Optional[dict] = None


class SessionUserInfoResponse(SessionUserResponse):
    bio: Optional[str] = None
    gender: Optional[str] = None
    date_of_birth: Optional[datetime.date] = None


@router.get("/", response_model=SessionUserInfoResponse)
async def get_session_user(
    request: Request, response: Response, user=Depends(get_current_user)
):

    auth_header = request.headers.get("Authorization")
    auth_token = get_http_authorization_cred(auth_header)
    token = auth_token.credentials
    data = decode_token(token)

    expires_at = None

    if data:
        expires_at = data.get("exp")

        if (expires_at is not None) and int(time.time()) > expires_at:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_MESSAGES.INVALID_TOKEN,
            )

        # Set the cookie token
        response.set_cookie(
            key="token",
            value=token,
            expires=(
                datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc)
                if expires_at
                else None
            ),
            httponly=True,  # Ensures the cookie is not accessible via JavaScript
            samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
            secure=WEBUI_AUTH_COOKIE_SECURE,
        )

    user_permissions = get_permissions(
        user.id, request.app.state.config.USER_PERMISSIONS
    )

    return {
        "token": token,
        "token_type": "Bearer",
        "expires_at": expires_at,
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "profile_image_url": user.profile_image_url,
        "bio": user.bio,
        "gender": user.gender,
        "date_of_birth": user.date_of_birth,
        "permissions": user_permissions,
    }


############################
# Update Profile
############################


@router.post("/update/profile", response_model=UserResponse)
async def update_profile(
    form_data: UpdateProfileForm, session_user=Depends(get_verified_user)
):
    if session_user:
        user = Users.update_user_by_id(
            session_user.id,
            form_data.model_dump(),
        )
        if user:
            return user
        else:
            raise HTTPException(400, detail=ERROR_MESSAGES.DEFAULT())
    else:
        raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_CRED)


############################
# Update Password
############################


@router.post("/update/password", response_model=bool)
async def update_password(
    form_data: UpdatePasswordForm, session_user=Depends(get_current_user)
):
    if WEBUI_AUTH_TRUSTED_EMAIL_HEADER:
        raise HTTPException(400, detail=ERROR_MESSAGES.ACTION_PROHIBITED)
    if session_user:
        user = Auths.authenticate_user(session_user.email, form_data.password)

        if user:
            hashed = get_password_hash(form_data.new_password)
            return Auths.update_user_password_by_id(user.id, hashed)
        else:
            raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_PASSWORD)
    else:
        raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_CRED)


############################
# LDAP Authentication
############################
@router.post("/ldap", response_model=SessionUserResponse)
async def ldap_auth(request: Request, response: Response, form_data: LdapForm):
    ENABLE_LDAP = request.app.state.config.ENABLE_LDAP
    LDAP_SERVER_LABEL = request.app.state.config.LDAP_SERVER_LABEL
    LDAP_SERVER_HOST = request.app.state.config.LDAP_SERVER_HOST
    LDAP_SERVER_PORT = request.app.state.config.LDAP_SERVER_PORT
    LDAP_ATTRIBUTE_FOR_MAIL = request.app.state.config.LDAP_ATTRIBUTE_FOR_MAIL
    LDAP_ATTRIBUTE_FOR_USERNAME = request.app.state.config.LDAP_ATTRIBUTE_FOR_USERNAME
    LDAP_SEARCH_BASE = request.app.state.config.LDAP_SEARCH_BASE
    LDAP_SEARCH_FILTERS = request.app.state.config.LDAP_SEARCH_FILTERS
    LDAP_APP_DN = request.app.state.config.LDAP_APP_DN
    LDAP_APP_PASSWORD = request.app.state.config.LDAP_APP_PASSWORD
    LDAP_USE_TLS = request.app.state.config.LDAP_USE_TLS
    LDAP_CA_CERT_FILE = request.app.state.config.LDAP_CA_CERT_FILE
    LDAP_VALIDATE_CERT = (
        CERT_REQUIRED if request.app.state.config.LDAP_VALIDATE_CERT else CERT_NONE
    )
    LDAP_CIPHERS = (
        request.app.state.config.LDAP_CIPHERS
        if request.app.state.config.LDAP_CIPHERS
        else "ALL"
    )

    if not ENABLE_LDAP:
        raise HTTPException(400, detail="LDAP authentication is not enabled")

    try:
        tls = Tls(
            validate=LDAP_VALIDATE_CERT,
            version=PROTOCOL_TLS,
            ca_certs_file=LDAP_CA_CERT_FILE,
            ciphers=LDAP_CIPHERS,
        )
    except Exception as e:
        log.error(f"TLS configuration error: {str(e)}")
        raise HTTPException(400, detail="Failed to configure TLS for LDAP connection.")

    try:
        server = Server(
            host=LDAP_SERVER_HOST,
            port=LDAP_SERVER_PORT,
            get_info=NONE,
            use_ssl=LDAP_USE_TLS,
            tls=tls,
        )
        connection_app = Connection(
            server,
            LDAP_APP_DN,
            LDAP_APP_PASSWORD,
            auto_bind="NONE",
            authentication="SIMPLE" if LDAP_APP_DN else "ANONYMOUS",
        )
        if not connection_app.bind():
            raise HTTPException(400, detail="Application account bind failed")

        ENABLE_LDAP_GROUP_MANAGEMENT = (
            request.app.state.config.ENABLE_LDAP_GROUP_MANAGEMENT
        )
        ENABLE_LDAP_GROUP_CREATION = request.app.state.config.ENABLE_LDAP_GROUP_CREATION
        LDAP_ATTRIBUTE_FOR_GROUPS = request.app.state.config.LDAP_ATTRIBUTE_FOR_GROUPS

        search_attributes = [
            f"{LDAP_ATTRIBUTE_FOR_USERNAME}",
            f"{LDAP_ATTRIBUTE_FOR_MAIL}",
            "cn",
        ]

        if ENABLE_LDAP_GROUP_MANAGEMENT:
            search_attributes.append(f"{LDAP_ATTRIBUTE_FOR_GROUPS}")
            log.info(
                f"LDAP Group Management enabled. Adding {LDAP_ATTRIBUTE_FOR_GROUPS} to search attributes"
            )

        log.info(f"LDAP search attributes: {search_attributes}")

        search_success = connection_app.search(
            search_base=LDAP_SEARCH_BASE,
            search_filter=f"(&({LDAP_ATTRIBUTE_FOR_USERNAME}={escape_filter_chars(form_data.user.lower())}){LDAP_SEARCH_FILTERS})",
            attributes=search_attributes,
        )

        if not search_success or not connection_app.entries:
            raise HTTPException(400, detail="User not found in the LDAP server")

        entry = connection_app.entries[0]
        username = str(entry[f"{LDAP_ATTRIBUTE_FOR_USERNAME}"]).lower()
        email = entry[
            f"{LDAP_ATTRIBUTE_FOR_MAIL}"
        ].value  # retrieve the Attribute value
        if not email:
            raise HTTPException(400, "User does not have a valid email address.")
        elif isinstance(email, str):
            email = email.lower()
        elif isinstance(email, list):
            email = email[0].lower()
        else:
            email = str(email).lower()

        cn = str(entry["cn"])
        user_dn = entry.entry_dn

        user_groups = []
        if ENABLE_LDAP_GROUP_MANAGEMENT and LDAP_ATTRIBUTE_FOR_GROUPS in entry:
            group_dns = entry[LDAP_ATTRIBUTE_FOR_GROUPS]
            log.info(f"LDAP raw group DNs for user {username}: {group_dns}")

            if group_dns:
                log.info(f"LDAP group_dns original: {group_dns}")
                log.info(f"LDAP group_dns type: {type(group_dns)}")
                log.info(f"LDAP group_dns length: {len(group_dns)}")

                if hasattr(group_dns, "value"):
                    group_dns = group_dns.value
                    log.info(f"Extracted .value property: {group_dns}")
                elif hasattr(group_dns, "__iter__") and not isinstance(
                    group_dns, (str, bytes)
                ):
                    group_dns = list(group_dns)
                    log.info(f"Converted to list: {group_dns}")

                if isinstance(group_dns, list):
                    group_dns = [str(item) for item in group_dns]
                else:
                    group_dns = [str(group_dns)]

                log.info(
                    f"LDAP group_dns after processing - type: {type(group_dns)}, length: {len(group_dns)}"
                )

                for group_idx, group_dn in enumerate(group_dns):
                    group_dn = str(group_dn)
                    log.info(f"Processing group DN #{group_idx + 1}: {group_dn}")

                    try:
                        group_cn = None

                        for item in group_dn.split(","):
                            item = item.strip()
                            if item.upper().startswith("CN="):
                                group_cn = item[3:]
                                break

                        if group_cn:
                            user_groups.append(group_cn)

                        else:
                            log.warning(
                                f"Could not extract CN from group DN: {group_dn}"
                            )
                    except Exception as e:
                        log.warning(
                            f"Failed to extract group name from DN {group_dn}: {e}"
                        )

                log.info(
                    f"LDAP groups for user {username}: {user_groups} (total: {len(user_groups)})"
                )
            else:
                log.info(f"No groups found for user {username}")
        elif ENABLE_LDAP_GROUP_MANAGEMENT:
            log.warning(
                f"LDAP Group Management enabled but {LDAP_ATTRIBUTE_FOR_GROUPS} attribute not found in user entry"
            )

        if username == form_data.user.lower():
            connection_user = Connection(
                server,
                user_dn,
                form_data.password,
                auto_bind="NONE",
                authentication="SIMPLE",
            )
            if not connection_user.bind():
                raise HTTPException(400, "Authentication failed.")

            user = Users.get_user_by_email(email)
            if not user:
                try:
                    role = (
                        "admin"
                        if not Users.has_users()
                        else request.app.state.config.DEFAULT_USER_ROLE
                    )

                    user = Auths.insert_new_auth(
                        email=email,
                        password=str(uuid.uuid4()),
                        name=cn,
                        role=role,
                    )

                    if not user:
                        raise HTTPException(
                            500, detail=ERROR_MESSAGES.CREATE_USER_ERROR
                        )

                except HTTPException:
                    raise
                except Exception as err:
                    log.error(f"LDAP user creation error: {str(err)}")
                    raise HTTPException(
                        500, detail="Internal error occurred during LDAP user creation."
                    )

            user = Auths.authenticate_user_by_email(email)

            if user:
                expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
                expires_at = None
                if expires_delta:
                    expires_at = int(time.time()) + int(expires_delta.total_seconds())

                token = create_token(
                    data={"id": user.id},
                    expires_delta=expires_delta,
                )

                # Set the cookie token
                response.set_cookie(
                    key="token",
                    value=token,
                    expires=(
                        datetime.datetime.fromtimestamp(
                            expires_at, datetime.timezone.utc
                        )
                        if expires_at
                        else None
                    ),
                    httponly=True,  # Ensures the cookie is not accessible via JavaScript
                    samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
                    secure=WEBUI_AUTH_COOKIE_SECURE,
                )

                user_permissions = get_permissions(
                    user.id, request.app.state.config.USER_PERMISSIONS
                )

                if (
                    user.role != "admin"
                    and ENABLE_LDAP_GROUP_MANAGEMENT
                    and user_groups
                ):
                    if ENABLE_LDAP_GROUP_CREATION:
                        Groups.create_groups_by_group_names(user.id, user_groups)

                    try:
                        Groups.sync_groups_by_group_names(user.id, user_groups)
                        log.info(
                            f"Successfully synced groups for user {user.id}: {user_groups}"
                        )
                    except Exception as e:
                        log.error(f"Failed to sync groups for user {user.id}: {e}")

                return {
                    "token": token,
                    "token_type": "Bearer",
                    "expires_at": expires_at,
                    "id": user.id,
                    "email": user.email,
                    "name": user.name,
                    "role": user.role,
                    "profile_image_url": user.profile_image_url,
                    "permissions": user_permissions,
                }
            else:
                raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_CRED)
        else:
            raise HTTPException(400, "User record mismatch.")
    except Exception as e:
        log.error(f"LDAP authentication error: {str(e)}")
        raise HTTPException(400, detail="LDAP authentication failed.")


############################
# SignIn
############################


@router.post("/signin", response_model=SessionUserResponse)
async def signin(request: Request, response: Response, form_data: SigninForm):
    if WEBUI_AUTH_TRUSTED_EMAIL_HEADER:
        if WEBUI_AUTH_TRUSTED_EMAIL_HEADER not in request.headers:
            raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_TRUSTED_HEADER)

        email = request.headers[WEBUI_AUTH_TRUSTED_EMAIL_HEADER].lower()
        name = email

        if WEBUI_AUTH_TRUSTED_NAME_HEADER:
            name = request.headers.get(WEBUI_AUTH_TRUSTED_NAME_HEADER, email)

        if not Users.get_user_by_email(email.lower()):
            await signup(
                request,
                response,
                SignupForm(email=email, password=str(uuid.uuid4()), name=name),
            )

        user = Auths.authenticate_user_by_email(email)
        if WEBUI_AUTH_TRUSTED_GROUPS_HEADER and user and user.role != "admin":
            group_names = request.headers.get(
                WEBUI_AUTH_TRUSTED_GROUPS_HEADER, ""
            ).split(",")
            group_names = [name.strip() for name in group_names if name.strip()]

            if group_names:
                Groups.sync_groups_by_group_names(user.id, group_names)

    elif WEBUI_AUTH == False:
        admin_email = "admin@localhost"
        admin_password = "admin"

        if Users.get_user_by_email(admin_email.lower()):
            user = Auths.authenticate_user(admin_email.lower(), admin_password)
        else:
            if Users.has_users():
                raise HTTPException(400, detail=ERROR_MESSAGES.EXISTING_USERS)

            await signup(
                request,
                response,
                SignupForm(email=admin_email, password=admin_password, name="User"),
            )

            user = Auths.authenticate_user(admin_email.lower(), admin_password)
    else:
        user = Auths.authenticate_user(form_data.email.lower(), form_data.password)

    if user:

        expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
        expires_at = None
        if expires_delta:
            expires_at = int(time.time()) + int(expires_delta.total_seconds())

        token = create_token(
            data={"id": user.id},
            expires_delta=expires_delta,
        )

        datetime_expires_at = (
            datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc)
            if expires_at
            else None
        )

        # Set the cookie token
        response.set_cookie(
            key="token",
            value=token,
            expires=datetime_expires_at,
            httponly=True,  # Ensures the cookie is not accessible via JavaScript
            samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
            secure=WEBUI_AUTH_COOKIE_SECURE,
        )

        user_permissions = get_permissions(
            user.id, request.app.state.config.USER_PERMISSIONS
        )

        return {
            "token": token,
            "token_type": "Bearer",
            "expires_at": expires_at,
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "role": user.role,
            "profile_image_url": user.profile_image_url,
            "permissions": user_permissions,
        }
    else:
        raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_CRED)


############################
# SignUp
############################


@router.post("/signup", response_model=SessionUserResponse)
async def signup(request: Request, response: Response, form_data: SignupForm):
    has_users = Users.has_users()

    if WEBUI_AUTH:
        if (
            not request.app.state.config.ENABLE_SIGNUP
            or not request.app.state.config.ENABLE_LOGIN_FORM
        ):
            if has_users or not ENABLE_INITIAL_ADMIN_SIGNUP:
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.ACCESS_PROHIBITED
                )
    else:
        if has_users:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.ACCESS_PROHIBITED
            )

    if not validate_email_format(form_data.email.lower()):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail=ERROR_MESSAGES.INVALID_EMAIL_FORMAT
        )

    if Users.get_user_by_email(form_data.email.lower()):
        raise HTTPException(400, detail=ERROR_MESSAGES.EMAIL_TAKEN)

    try:
        role = "admin" if not has_users else request.app.state.config.DEFAULT_USER_ROLE

        # The password passed to bcrypt must be 72 bytes or fewer. If it is longer, it will be truncated before hashing.
        if len(form_data.password.encode("utf-8")) > 72:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.PASSWORD_TOO_LONG,
            )

        # 在创建新用户前检查用户数量限制
        if role != "admin":
            limit_result = Users.enforce_user_limit(50)
            if limit_result.get("users_removed"):
                log.warning(f"用户数量达到限制，自动删除了 {len(limit_result['users_removed'])} 个非活跃用户")
                for removed_user in limit_result["users_removed"]:
                    log.info(f"自动删除用户: {removed_user['name']} ({removed_user['email']})")

        hashed = get_password_hash(form_data.password)
        user = Auths.insert_new_auth(
            form_data.email.lower(),
            hashed,
            form_data.name,
            form_data.profile_image_url,
            role,
        )

        # 检查管理员用户数量并发出警告
        if user and role == "admin":
            admin_count = Users.get_admin_users_count()
            total_count = Users.get_num_users()
            if total_count >= 50:
                log.warning(f"注意：系统用户总数已达到 {total_count} 人（管理员 {admin_count} 人），接近或超过50人限制")

        if user:
            expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
            expires_at = None
            if expires_delta:
                expires_at = int(time.time()) + int(expires_delta.total_seconds())

            token = create_token(
                data={"id": user.id},
                expires_delta=expires_delta,
            )

            datetime_expires_at = (
                datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc)
                if expires_at
                else None
            )

            # Set the cookie token
            response.set_cookie(
                key="token",
                value=token,
                expires=datetime_expires_at,
                httponly=True,  # Ensures the cookie is not accessible via JavaScript
                samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
                secure=WEBUI_AUTH_COOKIE_SECURE,
            )

            if request.app.state.config.WEBHOOK_URL:
                await post_webhook(
                    request.app.state.WEBUI_NAME,
                    request.app.state.config.WEBHOOK_URL,
                    WEBHOOK_MESSAGES.USER_SIGNUP(user.name),
                    {
                        "action": "signup",
                        "message": WEBHOOK_MESSAGES.USER_SIGNUP(user.name),
                        "user": user.model_dump_json(exclude_none=True),
                    },
                )

            user_permissions = get_permissions(
                user.id, request.app.state.config.USER_PERMISSIONS
            )

            if not has_users:
                # Disable signup after the first user is created
                request.app.state.config.ENABLE_SIGNUP = False

            return {
                "token": token,
                "token_type": "Bearer",
                "expires_at": expires_at,
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "role": user.role,
                "profile_image_url": user.profile_image_url,
                "permissions": user_permissions,
            }
        else:
            raise HTTPException(500, detail=ERROR_MESSAGES.CREATE_USER_ERROR)
    except Exception as err:
        log.error(f"Signup error: {str(err)}")
        raise HTTPException(500, detail="An internal error occurred during signup.")


@router.get("/signout")
async def signout(request: Request, response: Response):
    response.delete_cookie("token")
    response.delete_cookie("oui-session")
    response.delete_cookie("oauth_id_token")

    oauth_session_id = request.cookies.get("oauth_session_id")
    if oauth_session_id:
        response.delete_cookie("oauth_session_id")

        session = OAuthSessions.get_session_by_id(oauth_session_id)
        oauth_server_metadata_url = (
            request.app.state.oauth_manager.get_server_metadata_url(session.provider)
            if session
            else None
        ) or OPENID_PROVIDER_URL.value

        if session and oauth_server_metadata_url:
            oauth_id_token = session.token.get("id_token")
            try:
                async with ClientSession(trust_env=True) as session:
                    async with session.get(oauth_server_metadata_url) as r:
                        if r.status == 200:
                            openid_data = await r.json()
                            logout_url = openid_data.get("end_session_endpoint")

                            if logout_url:
                                return JSONResponse(
                                    status_code=200,
                                    content={
                                        "status": True,
                                        "redirect_url": f"{logout_url}?id_token_hint={oauth_id_token}"
                                        + (
                                            f"&post_logout_redirect_uri={WEBUI_AUTH_SIGNOUT_REDIRECT_URL}"
                                            if WEBUI_AUTH_SIGNOUT_REDIRECT_URL
                                            else ""
                                        ),
                                    },
                                    headers=response.headers,
                                )
                        else:
                            raise Exception("Failed to fetch OpenID configuration")

            except Exception as e:
                log.error(f"OpenID signout error: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail="Failed to sign out from the OpenID provider.",
                    headers=response.headers,
                )

    if WEBUI_AUTH_SIGNOUT_REDIRECT_URL:
        return JSONResponse(
            status_code=200,
            content={
                "status": True,
                "redirect_url": WEBUI_AUTH_SIGNOUT_REDIRECT_URL,
            },
            headers=response.headers,
        )

    return JSONResponse(
        status_code=200, content={"status": True}, headers=response.headers
    )


############################
# AddUser
############################


@router.post("/add", response_model=SigninResponse)
async def add_user(form_data: AddUserForm, user=Depends(get_admin_user)):
    if not validate_email_format(form_data.email.lower()):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail=ERROR_MESSAGES.INVALID_EMAIL_FORMAT
        )

    if Users.get_user_by_email(form_data.email.lower()):
        raise HTTPException(400, detail=ERROR_MESSAGES.EMAIL_TAKEN)

    try:
        # 在创建新用户前检查用户数量限制
        if form_data.role != "admin":
            limit_result = Users.enforce_user_limit(50)
            if limit_result.get("users_removed"):
                log.warning(f"用户数量达到限制，自动删除了 {len(limit_result['users_removed'])} 个非活跃用户")
                for removed_user in limit_result["users_removed"]:
                    log.info(f"自动删除用户: {removed_user['name']} ({removed_user['email']})")

        hashed = get_password_hash(form_data.password)
        user = Auths.insert_new_auth(
            form_data.email.lower(),
            hashed,
            form_data.name,
            form_data.profile_image_url,
            form_data.role,
        )

        # 检查管理员用户数量并发出警告
        if user and form_data.role == "admin":
            admin_count = Users.get_admin_users_count()
            total_count = Users.get_num_users()
            if total_count >= 50:
                log.warning(f"注意：系统用户总数已达到 {total_count} 人（管理员 {admin_count} 人），接近或超过50人限制")

        if user:
            token = create_token(data={"id": user.id})
            return {
                "token": token,
                "token_type": "Bearer",
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "role": user.role,
                "profile_image_url": user.profile_image_url,
            }
        else:
            raise HTTPException(500, detail=ERROR_MESSAGES.CREATE_USER_ERROR)
    except Exception as err:
        log.error(f"Add user error: {str(err)}")
        raise HTTPException(
            500, detail="An internal error occurred while adding the user."
        )


############################
# GetAdminDetails
############################


@router.get("/admin/details")
async def get_admin_details(request: Request, user=Depends(get_current_user)):
    if request.app.state.config.SHOW_ADMIN_DETAILS:
        admin_email = request.app.state.config.ADMIN_EMAIL
        admin_name = None

        log.info(f"Admin details - Email: {admin_email}, Name: {admin_name}")

        if admin_email:
            admin = Users.get_user_by_email(admin_email)
            if admin:
                admin_name = admin.name
        else:
            admin = Users.get_first_user()
            if admin:
                admin_email = admin.email
                admin_name = admin.name

        return {
            "name": admin_name,
            "email": admin_email,
        }
    else:
        raise HTTPException(400, detail=ERROR_MESSAGES.ACTION_PROHIBITED)


############################
# ToggleSignUp
############################


@router.get("/admin/config")
async def get_admin_config(request: Request, user=Depends(get_admin_user)):
    return {
        "SHOW_ADMIN_DETAILS": request.app.state.config.SHOW_ADMIN_DETAILS,
        "WEBUI_URL": request.app.state.config.WEBUI_URL,
        "ENABLE_SIGNUP": request.app.state.config.ENABLE_SIGNUP,
        "ENABLE_API_KEY": request.app.state.config.ENABLE_API_KEY,
        "ENABLE_API_KEY_ENDPOINT_RESTRICTIONS": request.app.state.config.ENABLE_API_KEY_ENDPOINT_RESTRICTIONS,
        "API_KEY_ALLOWED_ENDPOINTS": request.app.state.config.API_KEY_ALLOWED_ENDPOINTS,
        "DEFAULT_USER_ROLE": request.app.state.config.DEFAULT_USER_ROLE,
        "JWT_EXPIRES_IN": request.app.state.config.JWT_EXPIRES_IN,
        "ENABLE_COMMUNITY_SHARING": request.app.state.config.ENABLE_COMMUNITY_SHARING,
        "ENABLE_MESSAGE_RATING": request.app.state.config.ENABLE_MESSAGE_RATING,
        "ENABLE_CHANNELS": request.app.state.config.ENABLE_CHANNELS,
        "ENABLE_NOTES": request.app.state.config.ENABLE_NOTES,
        "ENABLE_USER_WEBHOOKS": request.app.state.config.ENABLE_USER_WEBHOOKS,
        "PENDING_USER_OVERLAY_TITLE": request.app.state.config.PENDING_USER_OVERLAY_TITLE,
        "PENDING_USER_OVERLAY_CONTENT": request.app.state.config.PENDING_USER_OVERLAY_CONTENT,
        "RESPONSE_WATERMARK": request.app.state.config.RESPONSE_WATERMARK,
    }


class AdminConfig(BaseModel):
    SHOW_ADMIN_DETAILS: bool
    WEBUI_URL: str
    ENABLE_SIGNUP: bool
    ENABLE_API_KEY: bool
    ENABLE_API_KEY_ENDPOINT_RESTRICTIONS: bool
    API_KEY_ALLOWED_ENDPOINTS: str
    DEFAULT_USER_ROLE: str
    JWT_EXPIRES_IN: str
    ENABLE_COMMUNITY_SHARING: bool
    ENABLE_MESSAGE_RATING: bool
    ENABLE_CHANNELS: bool
    ENABLE_NOTES: bool
    ENABLE_USER_WEBHOOKS: bool
    PENDING_USER_OVERLAY_TITLE: Optional[str] = None
    PENDING_USER_OVERLAY_CONTENT: Optional[str] = None
    RESPONSE_WATERMARK: Optional[str] = None


@router.post("/admin/config")
async def update_admin_config(
    request: Request, form_data: AdminConfig, user=Depends(get_admin_user)
):
    request.app.state.config.SHOW_ADMIN_DETAILS = form_data.SHOW_ADMIN_DETAILS
    request.app.state.config.WEBUI_URL = form_data.WEBUI_URL
    request.app.state.config.ENABLE_SIGNUP = form_data.ENABLE_SIGNUP

    request.app.state.config.ENABLE_API_KEY = form_data.ENABLE_API_KEY
    request.app.state.config.ENABLE_API_KEY_ENDPOINT_RESTRICTIONS = (
        form_data.ENABLE_API_KEY_ENDPOINT_RESTRICTIONS
    )
    request.app.state.config.API_KEY_ALLOWED_ENDPOINTS = (
        form_data.API_KEY_ALLOWED_ENDPOINTS
    )

    request.app.state.config.ENABLE_CHANNELS = form_data.ENABLE_CHANNELS
    request.app.state.config.ENABLE_NOTES = form_data.ENABLE_NOTES

    if form_data.DEFAULT_USER_ROLE in ["pending", "user", "admin"]:
        request.app.state.config.DEFAULT_USER_ROLE = form_data.DEFAULT_USER_ROLE

    pattern = r"^(-1|0|(-?\d+(\.\d+)?)(ms|s|m|h|d|w))$"

    # Check if the input string matches the pattern
    if re.match(pattern, form_data.JWT_EXPIRES_IN):
        request.app.state.config.JWT_EXPIRES_IN = form_data.JWT_EXPIRES_IN

    request.app.state.config.ENABLE_COMMUNITY_SHARING = (
        form_data.ENABLE_COMMUNITY_SHARING
    )
    request.app.state.config.ENABLE_MESSAGE_RATING = form_data.ENABLE_MESSAGE_RATING

    request.app.state.config.ENABLE_USER_WEBHOOKS = form_data.ENABLE_USER_WEBHOOKS

    request.app.state.config.PENDING_USER_OVERLAY_TITLE = (
        form_data.PENDING_USER_OVERLAY_TITLE
    )
    request.app.state.config.PENDING_USER_OVERLAY_CONTENT = (
        form_data.PENDING_USER_OVERLAY_CONTENT
    )

    request.app.state.config.RESPONSE_WATERMARK = form_data.RESPONSE_WATERMARK

    return {
        "SHOW_ADMIN_DETAILS": request.app.state.config.SHOW_ADMIN_DETAILS,
        "WEBUI_URL": request.app.state.config.WEBUI_URL,
        "ENABLE_SIGNUP": request.app.state.config.ENABLE_SIGNUP,
        "ENABLE_API_KEY": request.app.state.config.ENABLE_API_KEY,
        "ENABLE_API_KEY_ENDPOINT_RESTRICTIONS": request.app.state.config.ENABLE_API_KEY_ENDPOINT_RESTRICTIONS,
        "API_KEY_ALLOWED_ENDPOINTS": request.app.state.config.API_KEY_ALLOWED_ENDPOINTS,
        "DEFAULT_USER_ROLE": request.app.state.config.DEFAULT_USER_ROLE,
        "JWT_EXPIRES_IN": request.app.state.config.JWT_EXPIRES_IN,
        "ENABLE_COMMUNITY_SHARING": request.app.state.config.ENABLE_COMMUNITY_SHARING,
        "ENABLE_MESSAGE_RATING": request.app.state.config.ENABLE_MESSAGE_RATING,
        "ENABLE_CHANNELS": request.app.state.config.ENABLE_CHANNELS,
        "ENABLE_NOTES": request.app.state.config.ENABLE_NOTES,
        "ENABLE_USER_WEBHOOKS": request.app.state.config.ENABLE_USER_WEBHOOKS,
        "PENDING_USER_OVERLAY_TITLE": request.app.state.config.PENDING_USER_OVERLAY_TITLE,
        "PENDING_USER_OVERLAY_CONTENT": request.app.state.config.PENDING_USER_OVERLAY_CONTENT,
        "RESPONSE_WATERMARK": request.app.state.config.RESPONSE_WATERMARK,
    }


class LdapServerConfig(BaseModel):
    label: str
    host: str
    port: Optional[int] = None
    attribute_for_mail: str = "mail"
    attribute_for_username: str = "uid"
    app_dn: str
    app_dn_password: str
    search_base: str
    search_filters: str = ""
    use_tls: bool = True
    certificate_path: Optional[str] = None
    validate_cert: bool = True
    ciphers: Optional[str] = "ALL"


@router.get("/admin/config/ldap/server", response_model=LdapServerConfig)
async def get_ldap_server(request: Request, user=Depends(get_admin_user)):
    return {
        "label": request.app.state.config.LDAP_SERVER_LABEL,
        "host": request.app.state.config.LDAP_SERVER_HOST,
        "port": request.app.state.config.LDAP_SERVER_PORT,
        "attribute_for_mail": request.app.state.config.LDAP_ATTRIBUTE_FOR_MAIL,
        "attribute_for_username": request.app.state.config.LDAP_ATTRIBUTE_FOR_USERNAME,
        "app_dn": request.app.state.config.LDAP_APP_DN,
        "app_dn_password": request.app.state.config.LDAP_APP_PASSWORD,
        "search_base": request.app.state.config.LDAP_SEARCH_BASE,
        "search_filters": request.app.state.config.LDAP_SEARCH_FILTERS,
        "use_tls": request.app.state.config.LDAP_USE_TLS,
        "certificate_path": request.app.state.config.LDAP_CA_CERT_FILE,
        "validate_cert": request.app.state.config.LDAP_VALIDATE_CERT,
        "ciphers": request.app.state.config.LDAP_CIPHERS,
    }


@router.post("/admin/config/ldap/server")
async def update_ldap_server(
    request: Request, form_data: LdapServerConfig, user=Depends(get_admin_user)
):
    required_fields = [
        "label",
        "host",
        "attribute_for_mail",
        "attribute_for_username",
        "app_dn",
        "app_dn_password",
        "search_base",
    ]
    for key in required_fields:
        value = getattr(form_data, key)
        if not value:
            raise HTTPException(400, detail=f"Required field {key} is empty")

    request.app.state.config.LDAP_SERVER_LABEL = form_data.label
    request.app.state.config.LDAP_SERVER_HOST = form_data.host
    request.app.state.config.LDAP_SERVER_PORT = form_data.port
    request.app.state.config.LDAP_ATTRIBUTE_FOR_MAIL = form_data.attribute_for_mail
    request.app.state.config.LDAP_ATTRIBUTE_FOR_USERNAME = (
        form_data.attribute_for_username
    )
    request.app.state.config.LDAP_APP_DN = form_data.app_dn
    request.app.state.config.LDAP_APP_PASSWORD = form_data.app_dn_password
    request.app.state.config.LDAP_SEARCH_BASE = form_data.search_base
    request.app.state.config.LDAP_SEARCH_FILTERS = form_data.search_filters
    request.app.state.config.LDAP_USE_TLS = form_data.use_tls
    request.app.state.config.LDAP_CA_CERT_FILE = form_data.certificate_path
    request.app.state.config.LDAP_VALIDATE_CERT = form_data.validate_cert
    request.app.state.config.LDAP_CIPHERS = form_data.ciphers

    return {
        "label": request.app.state.config.LDAP_SERVER_LABEL,
        "host": request.app.state.config.LDAP_SERVER_HOST,
        "port": request.app.state.config.LDAP_SERVER_PORT,
        "attribute_for_mail": request.app.state.config.LDAP_ATTRIBUTE_FOR_MAIL,
        "attribute_for_username": request.app.state.config.LDAP_ATTRIBUTE_FOR_USERNAME,
        "app_dn": request.app.state.config.LDAP_APP_DN,
        "app_dn_password": request.app.state.config.LDAP_APP_PASSWORD,
        "search_base": request.app.state.config.LDAP_SEARCH_BASE,
        "search_filters": request.app.state.config.LDAP_SEARCH_FILTERS,
        "use_tls": request.app.state.config.LDAP_USE_TLS,
        "certificate_path": request.app.state.config.LDAP_CA_CERT_FILE,
        "validate_cert": request.app.state.config.LDAP_VALIDATE_CERT,
        "ciphers": request.app.state.config.LDAP_CIPHERS,
    }


@router.get("/admin/config/ldap")
async def get_ldap_config(request: Request, user=Depends(get_admin_user)):
    return {"ENABLE_LDAP": request.app.state.config.ENABLE_LDAP}


class LdapConfigForm(BaseModel):
    enable_ldap: Optional[bool] = None


@router.post("/admin/config/ldap")
async def update_ldap_config(
    request: Request, form_data: LdapConfigForm, user=Depends(get_admin_user)
):
    request.app.state.config.ENABLE_LDAP = form_data.enable_ldap
    return {"ENABLE_LDAP": request.app.state.config.ENABLE_LDAP}


############################
# API Key
############################


# create api key
@router.post("/api_key", response_model=ApiKey)
async def generate_api_key(request: Request, user=Depends(get_current_user)):
    if not request.app.state.config.ENABLE_API_KEY:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=ERROR_MESSAGES.API_KEY_CREATION_NOT_ALLOWED,
        )

    api_key = create_api_key()
    success = Users.update_user_api_key_by_id(user.id, api_key)

    if success:
        return {
            "api_key": api_key,
        }
    else:
        raise HTTPException(500, detail=ERROR_MESSAGES.CREATE_API_KEY_ERROR)


# delete api key
@router.delete("/api_key", response_model=bool)
async def delete_api_key(user=Depends(get_current_user)):
    success = Users.update_user_api_key_by_id(user.id, None)
    return success


############################
# Unified Identity Authentication OAuth 2.0
############################

class UnifiedOAuthCallbackRequest(BaseModel):
    code: str
    state: Optional[str] = None
    redirect_uri: str


async def process_oauth_callback_internal(
    request: Request,
    form_data: UnifiedOAuthCallbackRequest
) -> dict:
    """
    处理OAuth回调的核心逻辑（不涉及Response对象）
    返回包含用户信息和token的字典
    """
    log.info("开始处理统一身份认证OAuth回调")
    log.debug(f"接收到的参数: code={form_data.code[:10]}..., state={form_data.state}, redirect_uri={form_data.redirect_uri}")

    # OAuth 2.0 配置
    sso_server_url = SSO_SERVER_URL.value
    client_id = SSO_CLIENT_ID.value
    client_secret = SSO_CLIENT_SECRET.value

    log.debug(f"SSO配置: server_url={sso_server_url}, client_id={client_id}, client_secret={'***' if client_secret else 'None'}")

    if not sso_server_url or not client_id or not client_secret:
        log.error("OAuth 2.0客户端配置不完整")
        raise HTTPException(400, detail="OAuth 2.0客户端配置未设置")

    # 1. 使用授权码获取访问令牌
    token_url = f"{sso_server_url}/api-auth/oauth/token"
    token_data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": form_data.code,
        "redirect_uri": form_data.redirect_uri
    }

    log.info(f"正在向SSO服务器请求访问令牌: {token_url}")
    log.debug(f"请求参数: grant_type={token_data['grant_type']}, client_id={token_data['client_id']}, redirect_uri={token_data['redirect_uri']}")

    async with aiohttp.ClientSession() as session:
        async with session.post(token_url, data=token_data) as token_response:
            log.debug(f"SSO令牌响应状态: {token_response.status}")
            if token_response.status != 200:
                error_text = await token_response.text()
                log.error(f"获取访问令牌失败: {token_response.status} - {error_text}")
                log.error(f"请求URL: {token_url}")
                log.error(f"请求数据: {token_data}")
                raise HTTPException(400, detail=f"授权码验证失败: HTTP {token_response.status}")

            token_result = await token_response.json()
            log.debug(f"SSO令牌响应: {token_result}")
            access_token = token_result.get("access_token")

            if not access_token:
                log.error(f"SSO响应中未找到access_token: {token_result}")
                raise HTTPException(400, detail="未获取到访问令牌")

    # 2. 使用访问令牌获取用户信息
    check_token_url = f"{sso_server_url}/api-auth/oauth/check_token"
    check_token_params = {
        "token": access_token
    }

    log.info(f"正在验证访问令牌: {check_token_url}")
    log.debug(f"访问令牌: {access_token[:20]}...")

    async with aiohttp.ClientSession() as session:
        async with session.post(check_token_url, params=check_token_params) as check_response:
            log.debug(f"SSO令牌验证响应状态: {check_response.status}")
            if check_response.status != 200:
                error_text = await check_response.text()
                log.error(f"验证令牌失败: {check_response.status} - {error_text}")
                log.error(f"验证URL: {check_token_url}")
                log.error(f"令牌参数: token={access_token[:20]}...")
                raise HTTPException(400, detail=f"访问令牌验证失败: HTTP {check_response.status}")

            user_data = await check_response.json()
            log.debug(f"SSO用户信息响应: {user_data}")

            if not user_data.get("active"):
                log.error(f"SSO令牌未激活: {user_data}")
                raise HTTPException(400, detail="访问令牌已过期或无效")

    # 3. 处理用户信息并创建/更新用户
    username = user_data.get("user_name")
    authorities = user_data.get("authorities", [])
    client_id = user_data.get("client_id")

    log.info(f"处理SSO用户信息: username={username}, authorities={authorities}, client_id={client_id}")

    if not username:
        log.error("SSO响应中未找到用户名")
        raise HTTPException(400, detail="未获取到用户名信息")

    # 构建用户邮箱（如果SSO系统没有提供邮箱，使用用户名构建）
    email = f"{username}@{client_id}.local" if client_id else f"{username}@sso.local"
    log.debug(f"生成的用户邮箱: {email}")

    # 检查用户是否已存在
    user = Users.get_user_by_email(email.lower())
    log.debug(f"用户是否已存在: {'是' if user else '否'}")

    # 确定用户角色
    role = "user"  # 默认角色
    if "系统管理员" in authorities or "管理角色" in authorities:
        role = "admin"
        log.info(f"用户 {username} 具有管理员权限，分配admin角色")
    elif not Users.has_users():
        role = "admin"  # 第一个用户设为管理员
        log.info(f"用户 {username} 是系统第一个用户，分配admin角色")
    else:
        log.info(f"用户 {username} 分配普通用户角色")

    if not user:
        # 创建新用户前检查用户数量限制
        try:
            # 检查并执行用户数量限制（只对非管理员用户执行）
            if role != "admin":
                limit_result = Users.enforce_user_limit(50)
                if limit_result.get("users_removed"):
                    log.warning(f"用户数量达到限制，自动删除了 {len(limit_result['users_removed'])} 个非活跃用户")
                    for removed_user in limit_result["users_removed"]:
                        log.info(f"自动删除用户: {removed_user['name']} ({removed_user['email']})")

            user = Auths.insert_new_auth(
                email=email.lower(),
                password=get_password_hash(str(uuid.uuid4())),  # 随机密码，不会被使用
                name=username,
                role=role,
                profile_image_url="/user.png"
            )

            if not user:
                raise HTTPException(500, detail=ERROR_MESSAGES.CREATE_USER_ERROR)

            log.info(f"创建新的SSO用户: {email}, 角色: {role}")

            # 检查管理员用户数量并发出警告
            if role == "admin":
                admin_count = Users.get_admin_users_count()
                total_count = Users.get_num_users()
                if total_count >= 50:
                    log.warning(f"注意：系统用户总数已达到 {total_count} 人（管理员 {admin_count} 人），接近或超过50人限制")

            # 发送webhook通知
            if request.app.state.config.WEBHOOK_URL:
                await post_webhook(
                    request.app.state.WEBUI_NAME,
                    request.app.state.config.WEBHOOK_URL,
                    WEBHOOK_MESSAGES.USER_SIGNUP(user.name),
                    {
                        "action": "sso_signup",
                        "message": WEBHOOK_MESSAGES.USER_SIGNUP(user.name),
                        "user": user.model_dump_json(exclude_none=True),
                    },
                )

        except Exception as e:
            log.error(f"创建SSO用户失败: {e}")
            raise HTTPException(500, detail="用户创建失败")
    else:
        # 更新现有用户角色（如果权限发生变化）
        if user.role != role:
            Users.update_user_role_by_id(user.id, role)
            log.info(f"更新用户 {email} 的角色从 {user.role} 到 {role}")
            user.role = role

    # 4. 生成JWT令牌
    expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
    expires_at = None
    if expires_delta:
        expires_at = int(time.time()) + int(expires_delta.total_seconds())

    token = create_token(
        data={"id": user.id},
        expires_delta=expires_delta,
    )

    user_permissions = get_permissions(
        user.id, request.app.state.config.USER_PERMISSIONS
    )

    log.info(f"SSO用户 {email} 成功登录")

    return {
        "token": token,
        "token_type": "Bearer",
        "expires_at": expires_at,
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "profile_image_url": user.profile_image_url,
        "permissions": user_permissions,
    }


@router.post("/unified_oauth/callback", response_model=SessionUserResponse)
async def unified_oauth_callback(
    request: Request,
    response: Response,
    form_data: UnifiedOAuthCallbackRequest
):
    """
    处理统一身份认证系统的OAuth 2.0授权码模式回调
    支持外部系统页面跳转到本管理页面并根据授权码模式自动登录
    """
    try:
        # 检查统一身份认证是否启用
        if not ENABLE_UNIFIED_SSO.value:
            log.error("统一身份认证未启用")
            raise HTTPException(400, detail="统一身份认证未启用")

        # 调用内部处理函数
        auth_result = await process_oauth_callback_internal(request, form_data)

        # 设置cookie
        datetime_expires_at = (
            datetime.datetime.fromtimestamp(auth_result["expires_at"], datetime.timezone.utc)
            if auth_result.get("expires_at")
            else None
        )

        response.set_cookie(
            key="token",
            value=auth_result["token"],
            expires=datetime_expires_at,
            httponly=False,  # Required for frontend access
            samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
            secure=WEBUI_AUTH_COOKIE_SECURE,
        )

        return auth_result

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"统一身份认证OAuth回调处理失败: {e}")
        raise HTTPException(500, detail="身份认证处理失败")


@router.get("/unified_oauth/redirect")
async def unified_oauth_redirect(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None
):
    """
    处理来自统一身份认证系统的重定向回调（GET方式）
    这个端点用于接收授权码并重定向到前端处理页面
    """
    try:
        if error:
            # 认证失败，重定向到登录页面并显示错误
            redirect_url = f"/auth?error={error}"
            return RedirectResponse(url=redirect_url)

        if not code:
            # 没有授权码，重定向到登录页面
            redirect_url = "/auth?error=missing_authorization_code"
            return RedirectResponse(url=redirect_url)

        # 构建重定向URI（用于token请求）
        base_url = str(request.base_url).rstrip('/')
        redirect_uri = f"{base_url}/api/v1/auths/unified_oauth/redirect"

        # 自动调用回调处理
        callback_request = UnifiedOAuthCallbackRequest(
            code=code,
            state=state,
            redirect_uri=redirect_uri
        )

        # 直接处理OAuth回调逻辑（不通过Response对象）
        # 检查统一身份认证是否启用
        if not ENABLE_UNIFIED_SSO.value:
            log.error("统一身份认证未启用")
            raise HTTPException(400, detail="统一身份认证未启用")

        # 调用主要的OAuth处理逻辑
        auth_result = await process_oauth_callback_internal(request, callback_request)

        # 成功登录后创建重定向响应并设置cookie
        # 使用与现有OAuth系统相同的重定向逻辑
        redirect_base_url = str(request.app.state.config.WEBUI_URL or request.base_url)
        if redirect_base_url.endswith("/"):
            redirect_base_url = redirect_base_url[:-1]
        redirect_url = f"{redirect_base_url}/auth"

        redirect_response = RedirectResponse(url=redirect_url)

        # 设置认证cookie（与现有OAuth系统保持一致）
        redirect_response.set_cookie(
            key="token",
            value=auth_result["token"],
            httponly=False,  # Required for frontend access
            samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
            secure=WEBUI_AUTH_COOKIE_SECURE,
        )

        log.info(f"SSO认证成功，设置cookie并重定向到认证页面")
        log.debug(f"重定向URL: {redirect_url}")
        log.debug(f"Token前20位: {auth_result['token'][:20]}...")

        return redirect_response

    except HTTPException as e:
        # HTTP异常，重定向到登录页面并显示错误
        redirect_url = f"/auth?error={e.detail}"
        return RedirectResponse(url=redirect_url)
    except Exception as e:
        log.error(f"统一身份认证重定向处理失败: {e}")
        redirect_url = "/auth?error=authentication_failed"
        return RedirectResponse(url=redirect_url)


############################
# Unified SSO Configuration Management
############################

class UnifiedSSOConfig(BaseModel):
    enable_unified_sso: bool
    sso_server_url: str
    sso_client_id: str
    sso_client_secret: str


@router.get("/admin/config/unified_sso")
async def get_unified_sso_config(request: Request, user=Depends(get_admin_user)):
    """获取统一身份认证配置"""
    return {
        "ENABLE_UNIFIED_SSO": request.app.state.config.ENABLE_UNIFIED_SSO if hasattr(request.app.state.config, 'ENABLE_UNIFIED_SSO') else False,
        "SSO_SERVER_URL": request.app.state.config.SSO_SERVER_URL if hasattr(request.app.state.config, 'SSO_SERVER_URL') else "",
        "SSO_CLIENT_ID": request.app.state.config.SSO_CLIENT_ID if hasattr(request.app.state.config, 'SSO_CLIENT_ID') else "",
        "SSO_CLIENT_SECRET": "***" if (hasattr(request.app.state.config, 'SSO_CLIENT_SECRET') and request.app.state.config.SSO_CLIENT_SECRET) else ""
    }


@router.post("/admin/config/unified_sso")
async def update_unified_sso_config(
    request: Request,
    form_data: UnifiedSSOConfig,
    user=Depends(get_admin_user)
):
    """更新统一身份认证配置"""
    try:
        # 更新配置
        if not hasattr(request.app.state.config, 'ENABLE_UNIFIED_SSO'):
            request.app.state.config.ENABLE_UNIFIED_SSO = ENABLE_UNIFIED_SSO.value
        if not hasattr(request.app.state.config, 'SSO_SERVER_URL'):
            request.app.state.config.SSO_SERVER_URL = SSO_SERVER_URL.value
        if not hasattr(request.app.state.config, 'SSO_CLIENT_ID'):
            request.app.state.config.SSO_CLIENT_ID = SSO_CLIENT_ID.value
        if not hasattr(request.app.state.config, 'SSO_CLIENT_SECRET'):
            request.app.state.config.SSO_CLIENT_SECRET = SSO_CLIENT_SECRET.value

        request.app.state.config.ENABLE_UNIFIED_SSO = form_data.enable_unified_sso
        request.app.state.config.SSO_SERVER_URL = form_data.sso_server_url.rstrip('/')
        request.app.state.config.SSO_CLIENT_ID = form_data.sso_client_id

        # 只有在提供了新密码时才更新
        if form_data.sso_client_secret and form_data.sso_client_secret != "***":
            request.app.state.config.SSO_CLIENT_SECRET = form_data.sso_client_secret

        # 更新持久化配置
        ENABLE_UNIFIED_SSO.value = form_data.enable_unified_sso
        SSO_SERVER_URL.value = form_data.sso_server_url.rstrip('/')
        SSO_CLIENT_ID.value = form_data.sso_client_id
        if form_data.sso_client_secret and form_data.sso_client_secret != "***":
            SSO_CLIENT_SECRET.value = form_data.sso_client_secret

        return {
            "ENABLE_UNIFIED_SSO": request.app.state.config.ENABLE_UNIFIED_SSO,
            "SSO_SERVER_URL": request.app.state.config.SSO_SERVER_URL,
            "SSO_CLIENT_ID": request.app.state.config.SSO_CLIENT_ID,
            "SSO_CLIENT_SECRET": "***" if request.app.state.config.SSO_CLIENT_SECRET else ""
        }

    except Exception as e:
        log.error(f"更新统一身份认证配置失败: {e}")
        raise HTTPException(500, detail="配置更新失败")


@router.post("/admin/config/unified_sso/test")
async def test_unified_sso_connection(
    request: Request,
    user=Depends(get_admin_user)
):
    """测试统一身份认证服务器连接"""
    try:
        # 获取配置
        sso_server_url = SSO_SERVER_URL.value
        client_id = SSO_CLIENT_ID.value
        client_secret = SSO_CLIENT_SECRET.value

        if not sso_server_url or not client_id or not client_secret:
            return {
                "success": False,
                "message": "SSO配置不完整",
                "details": {
                    "sso_server_url": bool(sso_server_url),
                    "client_id": bool(client_id),
                    "client_secret": bool(client_secret)
                }
            }

        # 测试客户端授权模式（不需要用户授权）
        token_url = f"{sso_server_url}/api-auth/oauth/token"
        test_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials"
        }

        log.info(f"测试SSO连接: {token_url}")

        async with aiohttp.ClientSession() as session:
            async with session.post(token_url, data=test_data, timeout=10) as response:
                if response.status == 200:
                    result = await response.json()
                    return {
                        "success": True,
                        "message": "SSO服务器连接成功",
                        "details": {
                            "server_url": sso_server_url,
                            "client_id": client_id,
                            "token_type": result.get("token_type"),
                            "expires_in": result.get("expires_in")
                        }
                    }
                else:
                    error_text = await response.text()
                    return {
                        "success": False,
                        "message": f"SSO服务器响应错误 (HTTP {response.status})",
                        "details": {
                            "status_code": response.status,
                            "error": error_text,
                            "url": token_url
                        }
                    }

    except aiohttp.ClientError as e:
        return {
            "success": False,
            "message": "无法连接到SSO服务器",
            "details": {
                "error": str(e),
                "server_url": sso_server_url
            }
        }
    except Exception as e:
        log.error(f"测试SSO连接失败: {e}")
        return {
            "success": False,
            "message": "测试连接时发生错误",
            "details": {
                "error": str(e)
            }
        }


############################
# User Limit Management
############################

@router.get("/admin/users/stats")
async def get_user_stats(request: Request, user=Depends(get_admin_user)):
    """获取用户统计信息（管理员专用）"""
    try:
        total_users = Users.get_num_users()
        admin_users = Users.get_admin_users_count()
        non_admin_users = Users.get_non_admin_users_count()
        oldest_inactive_user = Users.get_oldest_inactive_non_admin_user()

        return {
            "total_users": total_users,
            "admin_users": admin_users,
            "non_admin_users": non_admin_users,
            "max_users": 50,
            "remaining_slots": max(0, 50 - total_users),
            "warning": total_users >= 50,
            "oldest_inactive_user": {
                "id": oldest_inactive_user.id,
                "name": oldest_inactive_user.name,
                "email": oldest_inactive_user.email,
                "last_active_at": oldest_inactive_user.last_active_at,
                "role": oldest_inactive_user.role
            } if oldest_inactive_user else None
        }
    except Exception as e:
        log.error(f"获取用户统计失败: {e}")
        raise HTTPException(500, detail="获取用户统计失败")


@router.post("/admin/users/enforce_limit")
async def enforce_user_limit_manual(request: Request, user=Depends(get_admin_user)):
    """手动执行用户数量限制（管理员专用）"""
    try:
        result = Users.enforce_user_limit(50)

        return {
            "success": True,
            "message": f"用户限制执行完成",
            "details": result
        }
    except Exception as e:
        log.error(f"执行用户限制失败: {e}")
        raise HTTPException(500, detail="执行用户限制失败")


@router.get("/debug/token")
async def debug_token_status(request: Request):
    """调试端点：检查当前token状态"""
    try:
        # 从cookie获取token
        token_cookie = request.cookies.get("token")

        # 从header获取token
        auth_header = request.headers.get("Authorization")
        auth_token = None
        if auth_header and auth_header.startswith("Bearer "):
            auth_token = auth_header[7:]

        return {
            "cookie_token": token_cookie[:20] + "..." if token_cookie else None,
            "header_token": auth_token[:20] + "..." if auth_token else None,
            "has_cookie_token": bool(token_cookie),
            "has_header_token": bool(auth_token),
            "cookies": dict(request.cookies),
            "headers": {
                "authorization": request.headers.get("Authorization"),
                "user-agent": request.headers.get("User-Agent"),
            }
        }
    except Exception as e:
        return {
            "error": str(e),
            "cookies": dict(request.cookies),
        }


# get api key
@router.get("/api_key", response_model=ApiKey)
async def get_api_key(user=Depends(get_current_user)):
    api_key = Users.get_user_api_key_by_id(user.id)
    if api_key:
        return {
            "api_key": api_key,
        }
    else:
        raise HTTPException(404, detail=ERROR_MESSAGES.API_KEY_NOT_FOUND)
