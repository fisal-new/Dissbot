import discord
import os

# أخذ التوكن من المتغير البيئي في Railway
TOKEN = os.environ.get("DISCORD_BOT_TOKEN")

# تفعيل صلاحيات قراءة الرسائل
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

@client.event
async def on_ready():
    print(f"✅ Bot is online as {client.user}")

@client.event
async def on_message(message):
    if message.author.bot:
        return

    if message.content.lower() == "!ping":
        await message.channel.send("🏓 Pong!")

    elif message.content.lower() == "!hello":
        await message.channel.send(f"👋 أهلاً، {message.author.name}!")

client.run(TOKEN)
