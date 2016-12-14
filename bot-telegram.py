#!/usr/bin/env python
# -*- coding: utf-8 -*-

import r2pipe
import logging
import urllib
import urllib2
import requests
import pydot
import os
import re
import feedparser
import subprocess
import ConfigParser
import magic
import hashlib
import mirai
import xorddos

from telegram.ext import Updater, CommandHandler, MessageHandler, Filters
from random import *
from datetime import datetime


Config = ConfigParser.ConfigParser()
Config.read("./config.conf")
ID = Config.get("GENERAL", "ID")

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
    #output = subprocess.Popen(["/home/pi/.local/bin/ipgeolocation.py", "-t" + args[0]], stdout=subprocess.PIPE).communicate()[0]
    loc = requests.get('https://ipapi.co/'+ args[0] + '/json/')

    json_result = loc.json()
    
    result = "IP: " + str(json_result['ip']) + "\n" + "Country: " + json_result['country'] + "\n" + "Region: " + json_result['region'] + "\n" + "City: " + json_result['city'] + "\n" + "Postal: " + json_result['postal'] + "\n" + "Timezone: " + str(json_result['timezone']) + "\n" + "Latitude: " + str(json_result['latitude']) + "\n"  + "Longitude: " + str(json_result['longitude'])


    bot.sendMessage(chat_id=chat_id, text=result)

def vt(bot,update, args):
    chat_id = update.message.chat_id
    output = subprocess.Popen(["/home/pi/Documents/Sources/Python/vt-tools/vthash.py", args[0]], stdout=subprocess.PIPE).communicate()[0]
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
    random_number= randint(1,4)
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

    filepath = "/tmp/mal"
    
    draft_dir = "/tmp/tmp_malw"

    try:
        urllib.urlretrieve (args[0], filepath)

        if (magic.from_file(filepath, mime=True) == "text/x-shellscript" or magic.from_file(filepath, mime=True) == "text/plain"):
            f = open(filepath, "r")
            toto=f.read()

            urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', toto)
    
            if urls != "":
                
                for url in urls:
                    
                    clean_url = re.sub('[!@#$;&|]', '', url)
                    
                    bot.sendMessage(chat_id=chat_id, text="Find payload: " + clean_url)

                    maliciousFile = draft_dir + "/" + os.path.basename(clean_url)

                    os.system("wget -q " + clean_url + " -O " +  maliciousFile )

                    command = "/usr/local/bin/yara -r /home/pi/Documents/Linux-malware.yar %s" % maliciousFile

                    output = subprocess.Popen(command , shell=True, stdout=subprocess.PIPE).communicate()[0]
                    hashmd5 = hashlib.md5(open(maliciousFile, 'rb').read()).hexdigest()
                    #output = subprocess.Popen(["/usr/bin/yara", "-r", "/home/pi/Documents/Linux-malware.yar " + maliciousFile], stdout=subprocess.PIPE).communicate()[0]
                    
                    value = output.split(' ')[0]
                    if value == "":
                        value = "Unknown sample"

                    bot.sendMessage(chat_id=chat_id, text=value + " MD5: " + hashmd5)

                    if 'mirai' in value.lower():
                        config = mirai.get_config(maliciousFile)
                    elif 'xor_ddos' in value.lower():
                        config = xorddos.get_config(maliciousFile)
                    else:   
                        config="Impossible to decrypt the configuration"

                    bot.sendMessage(chat_id=chat_id, text="Decrypted config:" + config)

                    os.system("rm " + maliciousFile)

            else:
                bot.sendMessage(chat_id=chat_id, text="Can't find url in the file")

        elif (magic.from_file(filepath, mime=True) == "application/x-executable"):

            output = subprocess.Popen(["/usr/local/bin/yara", "-r", "/home/pi/Documents/Linux-malware.yar", filepath], stdout=subprocess.PIPE).communicate()[0]
            hashmd5 = hashlib.md5(open(filepath, 'rb').read()).hexdigest()
            value = output.split(' ')[0]
            
            if value == "":
                value = "Unknown sample"

            bot.sendMessage(chat_id=chat_id, text=value + " MD5: " + hashmd5)

            if 'mirai' in value.lower():
                        config = mirai.get_config(filepath)
            elif 'xor_ddos' in value.lower():
                config = xorddos.get_config(filepath)
            else:   
                config="Impossible to decrypt the configuration"

            bot.sendMessage(chat_id=chat_id, text="Decrypted config:" + config)
            
            os.system("rm " + filepath)

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
