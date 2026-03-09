import configparser
import os
import pathlib

class Localization:
    def __init__(self,loc="ru"):
        self.loc = loc
        self.__loc_list=[]

    @property
    def loc(self):
        return self.__loc

    @loc.setter
    def loc(self,loc):
        self.config = configparser.ConfigParser()
        loc="localization/"+loc+".ini"

        self.config.read(loc, encoding='utf-8')
        self.flags=dict(self.config["Loc"])
        self.__loc = loc

    @property
    def loc_list(self):
        self.__loc_list=[]
        for p in pathlib.Path('localization/').glob('*.ini'):
            self.__loc_list.append(str(os.path.basename(p)))
        return self.__loc_list

    def get(self,name):
        try:
            return self.flags[name.lower()]
        except:
            return ""