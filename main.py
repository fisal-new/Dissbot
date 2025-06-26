import discord
import os
from keep_alive import keep_alive

TOKEN = os.environ.get("DISCORD_BOT_TOKEN")

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

    if message.content.lower() == "!hi":
        await message.channel.send(f"👋 Hello, {message.author.name}!")

keep_alive()
client.run(TOKEN)
