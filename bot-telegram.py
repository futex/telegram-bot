#!/usr/bin/env python
# -*- coding: utf-8 -*-

import r2pipe
import logging
import urllib
import pydot
import os
import urllib2
import feedparser
import subprocess

from telegram.ext import Updater, CommandHandler, MessageHandler, Filters
from random import *
from datetime import datetime

ID = ""

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.DEBUG)

logger = logging.getLogger(__name__)

def start(bot, update):
    update.message.reply_text('Hi!')

def mcstn(bot,update):
    chat_id = update.message.chat_id
    bot.sendMessage(chat_id=chat_id, text="Mes couilles sur ton nez, t'aura l'air d'un dindon!")

def ip(bot,update, args):
    chat_id = update.message.chat_id
    output = subprocess.Popen(["/home/pi/.local/bin/ipgeolocation.py", "-t" + args[0]], stdout=subprocess.PIPE).communicate()[0]
    bot.sendMessage(chat_id=chat_id, text=output)

def vt(bot,update, args):
    chat_id = update.message.chat_id
    output = subprocess.Popen(["/home/pi/Documents/Sources/Python/vt-tools/vthash2.py", args[0]], stdout=subprocess.PIPE).communicate()[0]
    bot.sendMessage(chat_id=chat_id, text=output)

def free(bot,update):
    chat_id = update.message.chat_id
    output = subprocess.Popen(["free", "-m"], stdout=subprocess.PIPE).communicate()[0]
    bot.sendMessage(chat_id=chat_id, text=output)

def uprecords(bot,update):
    chat_id = update.message.chat_id
    output = subprocess.Popen(["uprecords", ""], stdout=subprocess.PIPE).communicate()[0]
    bot.sendMessage(chat_id=chat_id, text=output)

def jmlp(bot,update):
    chat_id = update.message.chat_id
    random_number= randint(1,3)
    bot.sendPhoto(chat_id=chat_id, photo=open("/home/pi/Documents/Images/Meme/jm" + str(random_number) + ".jpeg","rb"))

def mmga(bot,update):
    chat_id = update.message.chat_id
    bot.sendPhoto(chat_id=chat_id, photo=open("/home/pi/Documents/Images/Meme/MakeMalwareGreatAgain.jpg","rb"))

def boobs(bot,update):
    chat_id = update.message.chat_id
    number = randrange(7630)
    url = 'http://media.oboobs.ru/boobs/0%s.jpg' % (str(number))
    
    filein = urllib2.urlopen(url)
    image = filein.read()
    filein.close()
    fileout = open("/tmp/boobs",'w+b')
    fileout.write(image)
    fileout.close()

    bot.sendPhoto(chat_id=chat_id, photo=open("/tmp/boobs","rb"))

def bonjour(bot, update):
    chat_id = update.message.chat_id

    madames = feedparser.parse("http://feeds2.feedburner.com/BonjourMadame")

    #for madame_du_jour in madames['entries']:
    #    adresse_madame_du_jour = madame_du_jour['summary_detail']['value'].split('"')[1]
    #    jour = str(datetime(*madame_du_jour.updated_parsed[:3])).split(' ')[0]
    #    if not os.path.isfile(jour+".jpg"):
    #        filein = urllib2.urlopen(adresse_madame_du_jour)
    #        image = filein.read()
    #        filein.close()
    #        fileout = open("/tmp/" + jour + ".jpg",'w+b')
    #        fileout.write(image)
    #        fileout.close()
    madame_du_jour = madames['entries'][0]['summary_detail']['value'].split('"')[1]

    filein = urllib2.urlopen(madame_du_jour)
    image = filein.read()
    filein.close()
    fileout = open("/tmp/bonjour.jpg",'w+b')
    fileout.write(image)
    fileout.close()

    bot.sendPhoto(chat_id=chat_id, photo=open("/tmp/bonjour.jpg","rb"))

def help(bot, update):
    update.message.reply_text('Help!')

def malware(bot, update, args):
    chat_id = update.message.chat_id
    try:
        urllib.urlretrieve (args[0], "/tmp/mal")
        output = subprocess.Popen(["/usr/bin/yara", "-r", "/home/pi/Documents/Linux-malware.yar", "/tmp/mal"], stdout=subprocess.PIPE).communicate()[0]
        value= output.split(' ')[0]
        
        if value == "":
            value = "unknown sample"

        bot.sendMessage(chat_id=chat_id, text=value)

        output = subprocess.Popen(["rm", "/tmp/mal"], stdout=subprocess.PIPE).communicate()[0]

    except (IndexError, ValueError):
        update.message.reply_text('Usage: /malware <URL>')
    except (IOError):
        update.message.reply_text('URL down')

def send_url(bot, update, args):
    chat_id = update.message.chat_id
    try:
        urllib.urlretrieve (args[0], "mal")
        r2 = r2pipe.open("/tmp/mal")
        bot.sendMessage(chat_id=chat_id, text=r2.cmd("fo"))
        bot.sendMessage(chat_id=chat_id, text="*SHA1: * " + r2.cmd("e file.sha1") + "*Architecture:* " + r2.cmdj("iIj")["arch"] + "\n*Machine:* " + r2.cmdj("iIj")["machine"],parse_mode="MARKDOWN")
        r2.cmd("aaa")
        r2.cmd("e scr.utf8=false")
        (graph,) = pydot.graph_from_dot_data(r2.cmd("ag entry0"))
        graph.write_png('graph.png')
        bot.sendPhoto(chat_id=chat_id, photo=open('/tmp/graph.png',"rb"))
    except (IndexError, ValueError):
        update.message.reply_text('Usage: /send_url <URL>')
    except (IOError):
        update.message.reply_text('URL down')

def error(bot, update, error):
    logger.warn('Update "%s" caused error "%s"' % (update, error))


def main():
    updater = Updater(ID)

    dp = updater.dispatcher

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("help", help))
    dp.add_handler(CommandHandler("bonjour", bonjour))
    dp.add_handler(CommandHandler("mcstn", mcstn))
    dp.add_handler(CommandHandler("boobs", boobs))
    dp.add_handler(CommandHandler("jmlp", jmlp))
    dp.add_handler(CommandHandler("mmga", mmga))
    dp.add_handler(CommandHandler("free", free))
    dp.add_handler(CommandHandler("uprecords", uprecords))
    dp.add_handler(CommandHandler("malware", malware, pass_args=True))
    dp.add_handler(CommandHandler("ip", ip, pass_args=True))
    dp.add_handler(CommandHandler("vt", vt, pass_args=True))
    dp.add_handler(CommandHandler("send_url", send_url, pass_args=True))

    dp.add_error_handler(error)
    
    updater.start_polling()

    updater.idle()


if __name__ == '__main__':
    main()
