import discord
from flask import Flask
from threading import Thread

# توكنك هنا مباشرة (بدون استخدام Secrets)
TOKEN = "MTM3OTg0NzYxMzE3MTYzMDA5MA.G1_SYb.obRtTPq7jRlTM_s9zjvcjfUT4oJkeEpB2R5X6A"

# إعدادات البوت
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# فل ask عشان نخلي البوت ما يطفي
app = Flask('')

@app.route('/')
def home():
    return "✅ Bot is Alive!"

def run():
    app.run(host='0.0.0.0', port=8080)

def keep_alive():
    t = Thread(target=run)
    t.start()

@client.event
async def on_ready():
    print(f"✅ Logged in as {client.user}")

@client.event
async def on_message(message):
    if message.author.bot:
        return
    if message.content.lower() == "بوت":
        await message.channel.send("هلا")

# تشغيل البوت
keep_alive()
client.run(TOKEN)
