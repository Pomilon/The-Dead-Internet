import asyncio
import os
import aiohttp
from aiohttp import web
import pwd
import json
import base64
import hashlib
from cryptography.fernet import Fernet

# Config
TOKEN_DIR = "/etc/psx/tokens"
ID_SERVICE = "http://id.psx"
BASE_PORT = 10000 # Agents will have proxy at 10000 + UID
SYSTEM_SECRET = os.getenv("SYSTEM_SECRET", "system-master-secret-key")

# Encryption Setup
ENC_KEY = base64.urlsafe_b64encode(hashlib.sha256(SYSTEM_SECRET.encode()).digest())
cipher = Fernet(ENC_KEY)

async def proxy_handler(request):
    # Identify which port the request came in on
    local_port = request.transport.get_extra_info('sockname')[1]
    uid = local_port - BASE_PORT
    
    if uid < 1000:
        return web.Response(status=403, text="Forbidden: System port access denied")

    try:
        username = pwd.getpwuid(uid).pw_name
    except KeyError:
        return web.Response(status=403, text=f"Forbidden: Unknown UID {uid}")

    # Load Token
    token_path = os.path.join(TOKEN_DIR, username)
    if not os.path.exists(token_path):
        return web.Response(status=401, text=f"Unauthorized: No token found for {username}")

    # Decrypt Token
    try:
        with open(token_path, "rb") as f:
            encrypted_token = f.read()
        token = cipher.decrypt(encrypted_token).decode('utf-8')
    except Exception as e:
        print(f"Token decryption failed for {username}: {e}")
        return web.Response(status=500, text="Internal Error: Token corruption")

    # Forward Request
    url = str(request.url)
    method = request.method
    headers = dict(request.headers)
    headers['Cookie'] = f"psx_auth={token}" # Standard cookie auth
    headers['Authorization'] = f"Bearer {token}" # Also add Bearer for APIs
    
    for h in ['Host', 'Connection', 'Keep-Alive', 'Proxy-Authenticate', 'Proxy-Authorization', 'TE', 'Trailers', 'Transfer-Encoding', 'Upgrade']:
        if h in headers: del headers[h]

    data = await request.read()

    async with aiohttp.ClientSession() as session:
        try:
            async with session.request(method, url, headers=headers, data=data, allow_redirects=False) as resp:
                body = await resp.read()
                response = web.Response(body=body, status=resp.status, headers=dict(resp.headers))
                return response
        except Exception as e:
            return web.Response(status=502, text=f"Proxy Error: {str(e)}")

async def main():
    server = web.Server(proxy_handler)
    runner = web.ServerRunner(server)
    await runner.setup()
    
    # We need to listen on many ports. 
    # For now, let's just listen on a range or dynamically add them?
    # Simpler: The agent_manager will just tell us which users to support.
    # For this simulation, let's just pre-bind a range (10000-10100).
    for uid in range(1000, 1100):
        port = BASE_PORT + uid
        site = web.TCPSite(runner, '127.0.0.1', port)
        try:
            await site.start()
        except:
            pass # Port might be in use
            
    print(f"PSX Multi-Port Proxy Active (Ports {BASE_PORT}+UID)")
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    asyncio.run(main())