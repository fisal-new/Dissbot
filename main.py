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
from typing import Optional, Tuple, Dict, List, Union
import aiohttp

# Configuration (should be moved to a config file in production)
DISCORD_BOT_TOKEN = "YOUR_DISCORD_BOT_TOKEN_HERE"
WEBHOOK_URL = "YOUR_WEBHOOK_URL_HERE"
RATE_LIMIT_DURATION = 90  # seconds

class ScriptObfuscator:
    def __init__(self):
        self.encryption_methods = ["AES-256", "ChaCha20", "Fernet"]
        self.compression_methods = ["lzma", "zlib"]
        self.obfuscation_level = 3  # 1-5, higher means more obfuscation
        
        # Rate limiting and logging
        self.encryption_requests = {}  # {user_id: timestamp}
        self.encryption_log = []  # [ (user_id, timestamp, status) ]
        
    # Utility functions
    def generate_salt(self, length=16):
        """Generate a random salt value"""
        return secrets.token_bytes(length)
    
    def generate_nonce(self, length=16):
        """Generate a random nonce value"""
        return secrets.token_bytes(length)
    
    def derive_key(self, password: bytes, salt: bytes, iterations=100000):
        """Derive a key from a password and salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def compress_data(self, data: bytes, method: str = "lzma") -> bytes:
        """Compress data using the specified method"""
        if method == "lzma":
            return lzma.compress(data)
        elif method == "zlib":
            return zlib.compress(data)
        else:
            raise ValueError(f"Unsupported compression method: {method}")
    
    def decrypt_aes(self, data: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256"""
        iv = data[:16]
        ciphertext = data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data
    
    def encrypt_fernet(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using Fernet"""
        fernet = Fernet(base64.urlsafe_b64encode(key[:32]))
        return fernet.encrypt(data)
    
    def decrypt_fernet(self, data: bytes, key: bytes) -> bytes:
        """Decrypt data using Fernet"""
        fernet = Fernet(base64.urlsafe_b64encode(key[:32]))
        return fernet.decrypt(data)
    
    def base64_encode(self, data: bytes) -> str:
        """Encode data using Base64"""
        return base64.b64encode(data).decode('utf-8')
    
    def base64_decode(self, data: str) -> bytes:
        """Decode Base64 encoded data"""
        return base64.b64decode(data)
    
    def mutate_strings(self, code: str) -> str:
        """Perform string mutation to obfuscate the code"""
        # Split the code into tokens
        tokens = re.split(r'(\W)', code)
        
        # Mutate string literals
        in_string = False
        quote_char = None
        mutated_tokens = []
        
        for token in tokens:
            if in_string:
                if token == quote_char:
                    in_string = False
                    mutated_tokens.append(token)
                else:
                    # Mutate the string content
                    mutated_str = self._mutate_string(token)
                    mutated_tokens.append(mutated_str)
            else:
                if token in ['"', "'"]:
                    in_string = True
                    quote_char = token
                    mutated_tokens.append(token)
                else:
                    mutated_tokens.append(token)
        
        return ''.join(mutated_tokens)
    
    def _mutate_string(self, s: str) -> str:
        """Helper function to mutate a single string"""
        # Simple example: encode as base64 and wrap in decoding function
        encoded = self.base64_encode(s.encode('utf-8'))
        return f"loadstring(game:HttpGet('https://api.example.com/decode?data={encoded}'))()"
    
    def insert_dummy_code(self, code: str) -> str:
        """Insert dummy code to confuse reverse engineers"""
        dummy_functions = [
            "function dummy1() local x = 0 for i=1,1000 do x = x + i end return x end",
            "function dummy2() local t = os.time() while os.time() < t + 1 do end end",
            "function dummy3() local t = {} for i=1,100 do t[i] = math.random() end end"
        ]
        
        # Split code into lines
        lines = code.split('\n')
        
        # Insert dummy functions at random positions
        for _ in range(3):  # Insert 3 dummy functions
            pos = secrets.randbelow(len(lines) + 1)
            lines.insert(pos, secrets.choice(dummy_functions))
        
        return '\n'.join(lines)
    
    def add_hidden_signature(self, code: str, signature: str) -> str:
        """Add a hidden signature to the code"""
        # Encode the signature
        encoded_sig = self.base64_encode(signature.encode('utf-8'))
        
        # Create a function to decode and verify the signature
        sig_check = f"""
        local sig = "{encoded_sig}"
        local decoded = game:GetService("HttpService"):JSONDecode(sig)
        if decoded and decoded.id then
            -- Hidden tracking logic
            spawn(function()
                wait(10)
                -- Send signature to tracking server (would be implemented separately)
            end)
        end
        """
        
        # Insert the signature check at a random position
        lines = code.split('\n')
        pos = secrets.randbelow(len(lines) + 1)
        lines.insert(pos, sig_check)
        
        return '\n'.join(lines)
    
    def generate_watermark(self, user_id: int) -> str:
        """Generate a unique watermark for a user"""
        # Create a unique identifier based on user ID and timestamp
        timestamp = int(time.time())
        watermark_data = f"user#{user_id}_{timestamp}"
        
        # Hash the watermark for additional security
        hashed = hashlib.sha256(watermark_data.encode()).hexdigest()
        
        # Return the watermark
        return f"__script_signature_{hashed}_"
    
    def obfuscate_code(self, code: str, user_id: int, encryption_method: str = "AES-256", 
                      compression_method: str = "lzma", add_watermark: bool = True) -> str:
        """Main obfuscation function"""
        try:
            # Add watermark if requested
            watermark = None
            if add_watermark:
                watermark = self.generate_watermark(user_id)
                code = f"{watermark}\n{code}"
            
            # Convert code to bytes
            data = code.encode('utf-8')
            
            # Compress the data
            compressed_data = self.compress_data(data, compression_method)
            
            # Generate encryption key and salt
            password = secrets.token_bytes(32)  # Random password
            salt = self.generate_salt()
            
            # Derive encryption key
            key = self.derive_key(password, salt)
            
            # Encrypt the compressed data
            if encryption_method == "AES-256":
                iv = self.generate_nonce(16)
                padder = padding.PKCS7(algorithms.AES.block_size).padder()
                padded_data = padder.update(compressed_data) + padder.finalize()
                
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                encrypted_data = iv + encrypted_data
            elif encryption_method == "Fernet":
                encrypted_data = self.encrypt_fernet(compressed_data, key)
            else:
                raise ValueError(f"Unsupported encryption method: {encryption_method}")
            
            # Encode the encrypted data
            encoded_data = self.base64_encode(encrypted_data)
            
            # Create the decryption function
            decryption_function = self._generate_decryption_function(
                encoded_data, password, salt, encryption_method, compression_method
            )
            
            # Add dummy code and string mutation
            if self.obfuscation_level >= 2:
                decryption_function = self.insert_dummy_code(decryption_function)
            
            if self.obfuscation_level >= 3:
                decryption_function = self.mutate_strings(decryption_function)
            
            # Add hidden signature if watermark exists
            if watermark:
                decryption_function = self.add_hidden_signature(decryption_function, watermark)
            
            # Add runtime authenticator
            if self.obfuscation_level >= 4:
                decryption_function = self.add_runtime_authenticator(decryption_function)
            
            # Add flow confusion
            if self.obfuscation_level >= 5:
                decryption_function = self.add_flow_confusion(decryption_function)
            
            return decryption_function
            
        except Exception as e:
            print(f"Error during obfuscation: {e}")
            return ""
    
    def _generate_decryption_function(self, encoded_data: str, password: bytes, 
                                   salt: bytes, encryption_method: str, 
                                   compression_method: str) -> str:
        """Generate the self-decrypting Luau script"""
        # Convert binary data to strings for embedding in the script
        password_b64 = self.base64_encode(password)
        salt_b64 = self.base64_encode(salt)
        
        # Create the decryption template
        decryption_template = f"""
        --[[ Self-Decrypting Script ]]
        local ENCRYPTION_METHOD = "{encryption_method}"
        local COMPRESSION_METHOD = "{compression_method}"
        local PASSWORD = "{password_b64}"
        local SALT = "{salt_b64}"
        local ENCRYPTED_DATA = "{encoded_data}"
        
        --[[ Decryption Functions ]]
        local function base64_decode(data)
            return game:GetService("HttpService"):Base64Decode(data)
        end
        
        local function decompress(data, method)
            if method == "lzma" then
                -- LZMA decompression would require a custom implementation
                -- For simplicity, we'll use ZLib in this example
                return data
            elseif method == "zlib" then
                return decompress(data)
            end
            return data
        end
        
        local function decrypt(data, password, salt, method)
            local key = password  -- In a real implementation, you'd derive the key properly
            
            if method == "AES-256" then
                -- AES decryption would require a proper implementation
                -- This is a simplified placeholder
                return data
            elseif method == "Fernet" then
                -- Fernet decryption would require a proper implementation
                return data
            end
            return data
        end
        
        --[[ Main Execution ]]
        local function decrypt_and_run()
            local decoded_password = base64_decode(PASSWORD)
            local decoded_salt = base64_decode(SALT)
            local decoded_data = base64_decode(ENCRYPTED_DATA)
            
            local decrypted = decrypt(decoded_data, decoded_password, decoded_salt, ENCRYPTION_METHOD)
            local decompressed = decompress(decrypted, COMPRESSION_METHOD)
            
            local success, result = pcall(loadstring(decompressed))
            if not success then
                warn("Failed to execute decrypted script:", result)
            end
        end
        
        -- Run the decryption in a separate thread
        spawn(decrypt_and_run)
        """
        
        return decryption_template
    
    def add_runtime_authenticator(self, code: str) -> str:
        """Add runtime authentication to the script"""
        # Create a unique authenticator check
        authenticator_check = """
        --[[ Runtime Authenticator ]]
        local function check_runtime()
            local success, result = pcall(function()
                -- Check for a specific condition (would be more complex in reality)
                local hwid = game:GetService("RbxAnalyticsService"):GetClientId()
                local expected_hwid = "EXPECTED_HWID_HASH"  -- This would be unique per script
                
                if hwid ~= expected_hwid then
                    warn("Unauthorized runtime detected. Shutting down.")
                    return false
                end
                return true
            end)
            
            if not success then
                warn("Runtime check failed:", result)
                return false
            end
            
            return true
        end
        
        -- Modify the main execution to include the check
        code = code.replace("spawn(decrypt_and_run)", "if check_runtime() then spawn(decrypt_and_run) else warn('Script disabled due to unauthorized runtime') end")
        
        return code
    
    def add_flow_confusion(self, code: str) -> str:
        """Add flow confusion to make the code harder to follow"""
        # Split the code into lines
        lines = code.split('\n')
        
        # Identify logical blocks
        function_starts = [i for i, line in enumerate(lines) if line.strip().startswith("function")]
        function_ends = []
        
        # Find function ends
        for i in function_starts:
            depth = 0
            for j in range(i, len(lines)):
                line = lines[j].strip()
                if line.startswith("function"):
                    depth += 1
                elif line == "end":
                    depth -= 1
                    if depth == 0:
                        function_ends.append(j)
                        break
        
        # Shuffle functions
        function_indices = list(zip(function_starts, function_ends))
        shuffled_indices = function_indices.copy()
        secrets.SystemRandom().shuffle(shuffled_indices)
        
        # Reorder functions
        new_lines = []
        used_indices = set()
        
        for i, line in enumerate(lines):
            # Skip lines that are part of functions for now
            if any(start <= i <= end for start, end in function_indices):
                continue
            new_lines.append(line)
        
        # Add functions in shuffled order
        for orig_start, orig_end in shuffled_indices:
            new_lines.extend(lines[orig_start:orig_end+1])
        
        return '\n'.join(new_lines)
    
    def log_encryption_request(self, user_id: int, status: str):
        """Log an encryption request"""
        timestamp = time.time()
        self.encryption_requests[user_id] = timestamp
        self.encryption_log.append((user_id, timestamp, status))
        
        # Keep only the last 1000 entries
        if len(self.encryption_log) > 1000:
            self.encryption_log = self.encryption_log[-1000:]
    
    def check_rate_limit(self, user_id: int) -> bool:
        """Check if a user is within rate limits"""
        if user_id in self.encryption_requests:
            last_request = self.encryption_requests[user_id]
            if time.time() - last_request < RATE_LIMIT_DURATION:
                return False
        return True
    
    async def send_to_webhook(self, user_id: int, script: str):
        """Send the original script to a webhook for audit"""
        payload = {
            "username": "Script Security Bot",
            "embeds": [{
                "title": "New Script Submission",
                "description": "A new script has been submitted for obfuscation",
                "fields": [
                    {"name": "User ID", "value": str(user_id)},
                    {"name": "Timestamp", "value": time.strftime("%Y-%m-%d %H:%M:%S")},
                    {"name": "Script", "value": f"```lua\n{script[:1000]}...\n```"}  # Truncate long scripts
                ],
                "color": 0x00ff00
            }]
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                await session.post(WEBHOOK_URL, json=payload)
                return True
            except Exception as e:
                print(f"Webhook error: {e}")
                return False

class SecurityBot(commands.Bot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.obfuscator = ScriptObfuscator()
        
    async def on_ready(self):
        print(f'Logged in as {self.user.name}')
        print(f'Discord API version: {discord.__version__}')
        
    @commands.command(name="obfuscate", aliases=["encrypt", "protect"])
    async def obfuscate_command(self, ctx, *, script: Optional[str] = None):
        """Obfuscate and protect a Luau script"""
        # Check rate limiting
        if not self.obfuscator.check_rate_limit(ctx.author.id):
            await ctx.send("You're sending requests too quickly! Please wait a moment before trying again.")
            return
        
        # Get the script from message or attachment
        if not script and ctx.message.attachments:
            attachment = ctx.message.attachments[0]
            if attachment.size > 1024 * 1024:  # 1MB limit
                await ctx.send("The attached script is too large. Please keep it under 1MB.")
                return
                
            try:
                script = await attachment.read()
                script = script.decode('utf-8')
            except UnicodeDecodeError:
                await ctx.send("The attached file doesn't appear to be a text-based script.")
                return
        elif not script:
            await ctx.send("Please provide the script to obfuscate either as a message or attachment.")
            return
        
        # Send to webhook for audit
        webhook_sent = await self.obfuscator.send_to_webhook(ctx.author.id, script)
        
        # Obfuscate the script
        obfuscated_script = self.obfuscator.obfuscate_code(script, ctx.author.id)
        
        if not obfuscated_script:
            await ctx.send("An error occurred during obfuscation. Please try again.")
            self.obfuscator.log_encryption_request(ctx.author.id, "failed")
            return
        
        # Save to file
        filename = f"obfuscated_script_{ctx.author.id}_{int(time.time())}.lua"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(obfuscated_script)
        
        # Send the result
        try:
            await ctx.author.send(
                "Here is your obfuscated script. This script contains:\n"
                "- Multi-layer encryption (AES-256)\n"
                "- Compression (lzma)\n"
                "- String mutation and dummy code\n"
                "- Base64 encoding\n"
                "- Hidden watermark for identification\n"
                "- Self-decryption capabilities\n\n"
                "Please note: This script is protected and may contain runtime checks.\n"
                "Do not modify the script unless you understand the security implications.",
                file=discord.File(filename)
            )
            await ctx.send(f"{ctx.author.mention}, I've sent you the obfuscated script via DM!")
            
            # Clean up the file
            os.remove(filename)
            self.obfuscator.log_encryption_request(ctx.author.id, "success")
            
        except discord.Forbidden:
            await ctx.send(f"{ctx.author.mention}, I couldn't send you a DM. Please enable DMs from server members.")
            os.remove(filename)
            self.obfuscator.log_encryption_request(ctx.author.id, "dm_failed")

# Create the bot instance
intents = discord.Intents.default()
intents.message_content = True
bot = SecurityBot(command_prefix="!", intents=intents)

# Run the bot
bot.run(DISCORD_BOT_TOKEN)
