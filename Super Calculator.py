from __future__ import division

import sys
import re
import math
import random
from binascii import hexlify, unhexlify
from base64 import b64decode, b64encode
from decimal import *

import sublime
import sublime_plugin


class SuperCalculatorCommand(sublime_plugin.TextCommand):

    def __init__(self, view):
        self.view = view
        self.settings = sublime.load_settings("Super Calculator.sublime-settings")
        self.callables = {}
        self.constants = {}
        for lib in (random, math):
            for key in dir(lib):
                attr = getattr(lib, key)
                if key[0] != '_':
                    if callable(attr):
                        self.callables[key] = attr
                    else:
                        self.constants[key] = attr
                        self.constants[key.upper()] = attr

        def average(nums):
            return sum(nums) / len(nums)

        self.callables['avg'] = average
        self.callables['average'] = average

        class Constant(object):
            def __init__(self, func):
                self._func = func

            def __call__(self, *args, **kwargs):
                return self._func(*args, **kwargs)

            def __repr__(self):
                return self._func()

        def password(length=16):
            pwdchrs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghjkmnopqrstuvwxyz0123456789'
            return ''.join(random.choice(pwdchrs) for _ in range(length))



        password = Constant(password)
        # self.callables['pwd'] = password
        self.callables['password'] = password
        # self.constants['pwd'] = password
        # self.constants['password'] = password
        # self.constants['PWD'] = password
        # self.constants['PASSWORD'] = password


        def unhexing(text):
            return unhexlify(text.encode('utf-8')).decode('utf-8')
        def hexing(text):
            return hexlify(text.encode('utf-8')).decode('utf-8')

        def intUnhex(num):
            return unhexlify(int(num))
        def intHex(num):
            return hexlify(int(num))

        def b64dec(str_in):
            return b64decode(str_in.encode('utf-8')).decode('utf-8')
        def b64enc(str_in):
            return b64encode(str_in.encode('utf-8')).decode('utf-8')

        unhexing = Constant(unhexing)
        hexing = Constant(hexing)
        intUnhex = Constant(intUnhex)
        intHex = Constant(intHex)
        b64dec = Constant(b64dec)
        b64enc = Constant(b64enc)

        self.callables['unhex'] = unhexing
        self.callables['hex'] = hexing
        self.callables['intunhex'] = intUnhex
        self.callables['inthex'] = intHex
        self.callables['atob'] = b64dec
        self.callables['btoa'] = b64enc

        allowed = '|'.join(
            [r'[-+*/%%()]'] +
            [r'\b[-+]?(\d*\.)?\d+\b'] +
            [r'\b%s\b' % c for c in self.constants.keys()] +
            [r'\b%s\s*\(' % c for c in self.callables.keys()]
        )
        self.regex = r'(%s)((%s|[ ])*(%s))?' % (allowed, allowed, allowed)
        self.dict = self.callables.copy()
        self.dict.update(self.constants)

        def generate_flag(flag, flag_len=16):
            alphabet="abcdefghijklmnopqrstuvwxyz"
            alphabet_capital="ABCDEFGHIJKLMNOPQRSTUVWXYZ"

            dictionary=[
                ["A","a","4","@"],
                ["B","b","8","6"],
                ["C","c"],
                ["D","d"],
                ["E","e","3"],
                ["F","f"],
                ["G","g","9"],
                ["H","h"],
                ["I","i","1"],
                ["J","j"],
                ["K","k"],
                ["L","l","1"],
                ["M","m"],
                ["N","n"],
                ["O","o","0"],
                ["P","p"],
                ["Q","q"],
                ["R","r"],
                ["S","s","5"],
                ["T","t","7"],
                ["U","u"],
                ["V","v"],
                ["W","w"],
                ["X","x"],
                ["Y","y"],
                ["Z","z","2"],
            ]

            new_flag=""
            for character in flag:
                if(character in alphabet):
                    new_flag += random.choice(dictionary[ord(character)-97])
                elif(character in alphabet_capital):
                    new_flag += random.choice(dictionary[ord(character)-65])
                else:
                    new_flag += character
            if(len(new_flag)+2 < flag_len):
                new_flag+="_"
                for x in range(flag_len - len(new_flag)):
                    # print(random.choice(random.choice(dictionary)))
                    new_flag += random.choice(random.choice(dictionary))
            return new_flag.replace(" ","_")
        generate_flag = Constant(generate_flag)
        self.callables['flag'] = generate_flag


    def run(self, edit):
        result_regions = []
        exprs = []
        for region in reversed(self.view.sel()):
            # Do the replacement in reverse order, so the character offsets
            # don't get invalidated
            exprs.append((region, self.view.substr(region)))
        for region, expr in exprs:
            if expr:
                # calculate expression and replace it with the result
                try:
                    result = str(eval(expr, self.dict, {}))
                except Exception as e:
                    sublime.status_message("Error: %s" % e)
                    continue
                else:
                    # round result if decimals are found
                    if '.' in result:
                        result = round(Decimal(result), self.settings.get("round_decimals"))
                    result = str(result)
                    if self.settings.get("trim_zeros") and '.' in result:
                        result =  result.strip('0').rstrip('.')
                        if result == '':
                            result = '0'
                    if result != expr:
                        self.view.replace(edit, region, result)
                        sublime.status_message("Calculated result: " + expr + "=" + result)
                    continue
            line_region = self.view.line(region)
            match_region = self.find_reverse(self.regex, region)
            if match_region:
                match = self.view.substr(match_region)
                # validate result and check if it is in the current line
                if re.match(self.regex, match) and line_region.begin() <= match_region.begin():
                    result_regions.append(match_region)
                    sublime.status_message("Calculate: " + match + "?")
        if result_regions:
            self.view.sel().clear()
            for region in result_regions:
                self.view.sel().add(region)

    def find_reverse(self, string, region):
        new_regions = (r for r in reversed(self.view.find_all(string))
            if r.begin() < region.end())
        try:
            if sys.version_info < (3,0,0) :
                new_region = new_regions.next()
            else :
                new_region = next(new_regions)
        except StopIteration:
            return None
        else:
            return new_region
