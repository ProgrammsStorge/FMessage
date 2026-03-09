import configparser
import os

class Config:
    def __init__(self,config_path):
        self.config_path = os.path.abspath(config_path)
        self.config = configparser.ConfigParser()
        self.config.read(self.config_path)
    def save_config(self):
        with open(self.config_path, 'w') as configfile:
            self.config.write(configfile)
    def get(self,title,key,default):
        if title in self.config and key in self.config[title]:
            return self.config[title][key]
        else:
            if not title in self.config:
                self.config.add_section(title)
                self.config[title] = {key:default}
            else:
                self.config[title].update({key:default})
            self.save_config()
            return default


