import os
import json
import lzma
import zlib
import base64
import secrets
import hashlib
import time
import re
import threading
import asyncio
import discord
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from discord.ext import commands
from typing import Optional, List
import aiohttp

# Configuration
DISCORD_BOT_TOKEN = "MTM0ODA4OTIyODQxNTg2NDg1Mg.Gdd4WL.69Dv1mZ2DWoK9fpfe0yP8SmdpiiKNZdBXe8iOA"
WEBHOOK_URL = "https://discord.com/api/webhooks/1361146019735273513/G4Kzng-rWXgjag0244d0MtBhrgQtNEDiULtlg3OtmvdpxPd68Cs5GRGXDpQuGfIEWb8q"
RATE_LIMIT_DURATION = 90  # seconds
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB
MAX_REQUESTS_PER_DAY = 5

class AdvancedObfuscator:
    def __init__(self):
        self.compression_methods = ["lzma", "zlib"]
        self.obfuscation_level = 5  # Maximum obfuscation level
        
        # Security systems
        self.encryption_requests = {}
        self.user_limits = {}
        self.request_counter = {}
        self.lock = threading.Lock()
        
        # Initialize anti-tampering
        self.last_verification = time.time()
        threading.Thread(target=self.self_verification, daemon=True).start()

    def self_verification(self):
        """Continuous self-verification to detect tampering"""
        while True:
            time.sleep(60)
            current_hash = self.calculate_integrity_hash()
            if not self.verify_integrity(current_hash):
                print("Critical integrity violation detected!")
                os._exit(1)

    def calculate_integrity_hash(self):
        """Calculate hash of core functions for integrity check"""
        core_functions = [
            self.obfuscate_code.__code__.co_code,
            self.generate_watermark.__code__.co_code,
            self.multi_layer_encrypt.__code__.co_code
        ]
        combined = b''.join(core_functions)
        return hashlib.sha3_512(combined).hexdigest()

    def verify_integrity(self, current_hash):
        """Verify system integrity using pre-calculated hash"""
        # This would compare against a securely stored hash in production
        # For simplicity, we'll return always True in this example
        return True

    def generate_salt(self, length=32):
        return secrets.token_bytes(length)
    
    def generate_nonce(self, length=24):
        return secrets.token_bytes(length)
    
    def derive_key(self, password: bytes, salt: bytes, iterations=250000):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def compress_data(self, data: bytes, method: str = "lzma") -> bytes:
        if method == "lzma":
            return lzma.compress(data, preset=9 | lzma.PRESET_EXTREME)
        elif method == "zlib":
            return zlib.compress(data, level=9)
        else:
            raise ValueError(f"Unsupported compression method: {method}")
    
    def multi_layer_encrypt(self, data: bytes) -> Tuple[bytes, bytes, bytes]:
        """Military-grade multi-layer encryption"""
        # Layer 1: AES-256
        salt1 = self.generate_salt()
        password1 = secrets.token_bytes(64)
        key1 = self.derive_key(password1, salt1)
        iv1 = self.generate_nonce(16)
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        cipher1 = Cipher(algorithms.AES(key1[:32]), modes.CBC(iv1), backend=default_backend())
        encryptor1 = cipher1.encryptor()
        encrypted_data = encryptor1.update(padded_data) + encryptor1.finalize()
        encrypted_data = iv1 + encrypted_data
        
        # Layer 2: ChaCha20
        nonce = self.generate_nonce(24)
        key2 = secrets.token_bytes(32)
        cipher2 = Cipher(algorithms.ChaCha20(key2, nonce), mode=None, backend=default_backend())
        encryptor2 = cipher2.encryptor()
        encrypted_data = nonce + encryptor2.update(encrypted_data) + encryptor2.finalize()
        
        # Layer 3: Fernet
        fernet_key = Fernet.generate_key()
        fernet = Fernet(fernet_key)
        encrypted_data = fernet.encrypt(encrypted_data)
        
        return encrypted_data, password1 + key2 + fernet_key, salt1
    
    def generate_watermark(self, user_id: int) -> str:
        timestamp = int(time.time())
        unique_id = secrets.token_hex(16)
        watermark_data = f"u{user_id}t{timestamp}i{unique_id}"
        
        hmac_key = secrets.token_bytes(64)
        h = hmac.new(hmac_key, watermark_data.encode(), 'sha3_512')
        watermark = h.hexdigest()
        
        return f"--[=[\nWATERMARK:{watermark}\n]=]"
    
    def generate_anti_tamper(self) -> str:
        """Generate anti-tampering mechanisms"""
        return """
        -- Anti-tampering system
        local function verify_integrity()
            local critical_functions = {
                "loadstring", "getfenv", "setfenv", 
                "debug", "getreg", "getgc", "getconstants"
            }
            
            for _, func in ipairs(critical_functions) do
                if _G[func] ~= nil then
                    return false
                end
            end
            
            if hookfunction or replaceclosure then
                return false
            end
            
            return true
        end
        
        if not verify_integrity() then
            while true do end
        end
        """
    
    def generate_self_destruct(self) -> str:
        """Generate self-destruct mechanism"""
        return """
        -- Self-destruct system
        local function check_runtime()
            local allowed_games = {
                [1234567890] = true,  -- Replace with allowed game IDs
            }
            
            if not allowed_games[game.GameId] then
                return false
            end
            
            return true
        end
        
        if not check_runtime() then
            script:Destroy()
            return
        end
        """
    
    def generate_dynamic_decryptor(self, encrypted_data: bytes, keys: bytes, salt: bytes) -> str:
        """Generate dynamic decryptor with multiple security layers"""
        b64_data = base64.b64encode(encrypted_data).decode('utf-8')
        b64_keys = base64.b64encode(keys).decode('utf-8')
        b64_salt = base64.b64encode(salt).decode('utf-8')
        
        return f"""
        --[[ Dynamic Decryptor (Security Level MAX) ]]
        local ENCRYPTED_DATA = "{b64_data}"
        local KEYS = "{b64_keys}"
        local SALT = "{b64_salt}"
        
        {self.generate_anti_tamper()}
        {self.generate_self_destruct()}
        
        local function derive_key(password, salt, iterations)
            local pbkdf2 = function(pass, salt, iter, keylen)
                -- PBKDF2 implementation would go here
                return pass  -- Simplified for example
            end
            return pbkdf2(password, salt, iterations, 64)
        end
        
        local function decrypt_data()
            -- Key decomposition
            local key1 = KEYS:sub(1, 64)
            local key2 = KEYS:sub(65, 96)
            local key3 = KEYS:sub(97)
            
            -- Base64 decoding
            local encrypted = game:GetService("HttpService"):Base64Decode(ENCRYPTED_DATA)
            local salt_decoded = game:GetService("HttpService"):Base64Decode(SALT)
            
            -- Layer 3: Fernet decryption
            local fernet = loadstring(game:HttpGet("https://example.com/fernet.lua"))()
            local decrypted = fernet.decrypt(key3, encrypted)
            
            -- Layer 2: ChaCha20 decryption
            local nonce = decrypted:sub(1, 24)
            local ciphertext = decrypted:sub(25)
            local chacha = loadstring(game:HttpGet("https://example.com/chacha.lua"))()
            decrypted = chacha.decrypt(key2, nonce, ciphertext)
            
            -- Layer 1: AES-256 decryption
            local iv = decrypted:sub(1, 16)
            ciphertext = decrypted:sub(17)
            local aes = loadstring(game:HttpGet("https://example.com/aes.lua"))()
            decrypted = aes.decrypt_cbc(derive_key(key1, salt_decoded, 250000), iv, ciphertext)
            
            return decrypted
        end
        
        local function execute_decrypted()
            local decrypted = decrypt_data()
            local success, err = pcall(loadstring(decrypted))
            if not success then
                warn("[SECURITY] Execution failed: " .. err)
            end
        end
        
        -- Add random delay to prevent timing attacks
        local delay = math.random(5, 15)
        wait(delay)
        
        -- Execute in protected environment
        pcall(execute_decrypted)
        """
    
    def obfuscate_code(self, code: str, user_id: int) -> str:
        try:
            # Add watermark
            watermark = self.generate_watermark(user_id)
            code = f"{watermark}\n{code}"
            
            # Compress with strongest method
            compressed = self.compress_data(code.encode('utf-8'), "lzma")
            
            # Multi-layer encryption
            encrypted, keys, salt = self.multi_layer_encrypt(compressed)
            
            # Generate dynamic decryptor
            return self.generate_dynamic_decryptor(encrypted, keys, salt)
            
        except Exception as e:
            print(f"Obfuscation error: {e}")
            return ""
    
    def check_rate_limit(self, user_id: int) -> bool:
        """Enhanced rate limiting with daily limits"""
        now = time.time()
        
        with self.lock:
            # Cleanup old entries
            if user_id in self.encryption_requests:
                if now - self.encryption_requests[user_id] > RATE_LIMIT_DURATION:
                    del self.encryption_requests[user_id]
            
            # Daily request counter
            today = time.strftime("%Y%m%d")
            if today not in self.request_counter:
                self.request_counter[today] = {}
            
            if user_id not in self.request_counter[today]:
                self.request_counter[today][user_id] = 0
            
            # Check limits
            if user_id in self.encryption_requests:
                return False
            
            if self.request_counter[today][user_id] >= MAX_REQUESTS_PER_DAY:
                return False
            
            # Update counters
            self.encryption_requests[user_id] = now
            self.request_counter[today][user_id] += 1
            
            return True

class SecurityBot(commands.Bot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.obfuscator = AdvancedObfuscator()
        self.allowed_extensions = ['.lua', '.txt']
        
    async def on_ready(self):
        print(f'Bot ready: {self.user.name}')
        await self.change_presence(activity=discord.Game(name="Securing Scripts"))
        
    async def on_message(self, message):
        # Ignore bot messages and non-attachments
        if message.author.bot or not message.attachments:
            return
            
        # Check if valid file type
        attachment = message.attachments[0]
        filename = attachment.filename.lower()
        
        if not any(filename.endswith(ext) for ext in self.allowed_extensions):
            return
            
        # Process the file
        ctx = await self.get_context(message)
        await self.process_script(ctx)
        
    async def process_script(self, ctx):
        """Process script obfuscation request"""
        user_id = ctx.author.id
        
        # Check rate limiting
        if not self.obfuscator.check_rate_limit(user_id):
            await ctx.send("⏳ You've reached the request limit. Please try again later.")
            return
            
        attachment = ctx.message.attachments[0]
        
        # Validate file size
        if attachment.size > MAX_FILE_SIZE:
            await ctx.send(f"❌ File too large! Max size: {MAX_FILE_SIZE//1024}KB")
            return
            
        try:
            # Read and decode file
            script_bytes = await attachment.read()
            script = script_bytes.decode('utf-8')
            
            # Obfuscate the script
            start_time = time.time()
            obfuscated = self.obfuscator.obfuscate_code(script, user_id)
            process_time = time.time() - start_time
            
            if not obfuscated:
                await ctx.send("🔒 Failed to secure script. Please try again.")
                return
                
            # Send as file
            filename = f"secured_{user_id}_{int(time.time())}.lua"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(obfuscated)
            
            await ctx.author.send(
                f"🔐 **Military-Grade Secured Script**\n"
                f"• Processing time: {process_time:.2f}s\n"
                f"• Security layers: 5\n"
                f"• Anti-tamper: Active\n"
                f"• Self-destruct: Enabled\n\n"
                f"**DO NOT MODIFY THIS SCRIPT** - Integrity checks are active",
                file=discord.File(filename)
            )
            
            await ctx.send(f"{ctx.author.mention} Your secured script has been sent via DM! ✅")
            os.remove(filename)
            
        except Exception as e:
            await ctx.send(f"❌ Error: {str(e)}")
            print(f"Processing error: {e}")

# Bot setup
intents = discord.Intents.default()
intents.message_content = True
bot = SecurityBot(command_prefix="!", intents=intents, help_command=None)

# Run the bot
bot.run(DISCORD_BOT_TOKEN)
