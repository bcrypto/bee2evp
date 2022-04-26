# *****************************************************************************
# \file patching.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief OpenSSL patching to support BTLS ciphersuites
# \created 2022.03.22
# \version 2022.04.26
# \license This program is released under the GNU General Public License 
# version 3 with the additional exemption that compiling, linking, 
# and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
# *****************************************************************************

import os
import re
import json
import multiline


def search_array(content, array_name):
    start_idx = re.search(rf"static.*{array_name}", content).start()
    # content.find(fr'static.*{array_name}')
    # start_idx = content.find('{', start_idx)
    end_idx = content.find('};', start_idx)
    return content[start_idx:end_idx + 1]


def search_macro(content, macro_name):
    macro_code = re.search(rf"#(\s*)define.*{macro_name}(\s+[\w\s|()\\]+\\?\n)+\n",
                           content)
    return macro_code[0]


def search_func(content, func_name):
    start_idx = re.search(rf"\w+\s\**{func_name}[^\;^\n]*\n", content).start()
    # end_idx = re.search(r"return\s+\w+;\n+\}", content[start_idx:]).end()
    end_idx = re.search(r"\n\}\n", content[start_idx:]).end()
    #if func_name == "tls_process_client_key_exchange":
    #    print(content[start_idx:end_idx + start_idx + 1])

    # print('############################')
    # func_code = re.search(rf"\w+\s{func_name}", content)
    return content[start_idx:end_idx + start_idx + 1]


class Patch:
    def __init__(self, patch_file):
        with open("ssl/build.info", 'r') as f:
            info_lines = f.readlines()
        with open("ssl/build.info", 'w') as f:
            info_lines[-1] = info_lines[-1][:-1] + " btls.c\n"
            f.writelines(info_lines)

        with open(patch_file, 'r') as f:
            patch = f.read()

        res = multiline.loads(patch, multiline=True)
        # print(str(res))

        files = res.keys()
        for file in files:
            print(file)
            static_arrays_dict = res[file].get('static_arrays')
            static_arrays = {}
            if static_arrays_dict:
                static_arrays = static_arrays_dict.values()

            functions_dict = res[file].get('functions')
            functions = {}
            if functions_dict:
                functions = functions_dict.values()

            macros_dict = res[file].get("macros")
            macros = {}
            if macros_dict:
                macros = macros_dict.values()

            with open(file, 'r') as f:
                content = f.read()

            if file in ["ssl/s3_lib.c", "ssl/ssl_ciph.c", "ssl/ssl_cert_table.h",
                        "ssl/ssl_lib.c", "ssl/t1_lib.c"]:
                content = '# include "btls.h"\n' + content
            if file in ["ssl/ssl_local.h"]:
                pos = content.find("# include")
                content = content[:pos] + '# include "btls.h"\n' + content[pos:]

            for array in static_arrays:
                a = array['array_name']
                arr_code = search_array(content, array['array_name'])
                arr_obj = StaticArray(arr_code)
                for value in array['values'].values():
                    arr_obj.append2c(value)
                content = content.replace(arr_code, arr_obj.p2c())

            for func in functions:
                f = func['func_name']
                f_code = search_func(content, f)
                f_obj = Function(f_code)
                code2add = func.get('code')
                end_flag = func.get('to_end')
                if code2add != '' and end_flag:
                    f_obj.add_to_end(code2add)

                switch_cond = func.get('switch_name')
                if code2add != '' and switch_cond:
                    f_obj.add_to_switch(switch_cond, code2add)

                insert_before = func.get('insert_before')
                if code2add != '' and insert_before:
                    f_obj.insert_before(insert_before, code2add)

                change_if = func.get("change_if")
                if code2add != '' and change_if:
                    f_obj.add_to_if_cond(change_if, code2add)

                content = content.replace(f_code, f_obj.get_code())

            for macro in macros:
                m = macro['macro_name']
                m_code = search_macro(content, m)
                m_obj = Macro(m_code)
                new_value = macro.get('new_value')
                if new_value != '':
                    m_obj.set_value(new_value)

                content = content.replace(m_code, m_obj.p2c())

            with open(file, "w") as f:
                f.write(content)


class Macro:
    def __init__(self, c):
        self.c = c
        # self.value = re.search(r"(\s+[\w\s|()\\]+\\?\n)+\n", c)
        tmp = self.c.split(' ', maxsplit=2)
        self.value = tmp[1] if tmp[0] == '#' else tmp[2]

    def p2c(self):
        return '# define ' + self.value + '\n'

    def set_value(self, value):
        self.value = value


class Function:
    def __init__(self, c):
        self.c = c

    def change_loop_condition(self, old_cond, new_cond):
        start_pos = self.c.find(old_cond)

    def add_to_end(self, code):
        start_pos = self.c.rfind("return")
        self.c = self.c[:start_pos] + code + '\n\t' + self.c[start_pos:]

    def add_to_switch(self, switch_cond, new_case):
        # print(self.c)
        start_pos = re.search(rf"switch\s*\({switch_cond}\)", self.c).start()
        start_pos = self.c.find("case",  start_pos)
        self.c = self.c[:start_pos] + new_case + self.c[start_pos:]

    def add_to_if_cond(self, cond, new_cond):
        #print(cond)
        #print(new_cond)
        #print(self.c)
        # self.c = re.sub(rf"if\s*{cond}", "if " + new_cond, self.c)

        p = re.escape(cond)
        #print(p)
        a = re.search(rf"if\s*{p}", self.c)
        #if cond[:10] == "    else {":
        #    print(p)
        #    print(a)
        #    print(self.c)
        self.c = re.sub(rf"if\s*{p}", "if " + new_cond, self.c)
        #print(self.c)

    def insert_before(self, before_line, new_code):
        start_pos = self.c.find(before_line)
        self.c = self.c[:start_pos] + new_code + self.c[start_pos:]

    def add_if(self, code_before, new_if):
        start_pos = self.c.find(code_before)
        self.c = self.c[:start_pos] + '\n' + new_if + '\n\t' + self.c[start_pos:]

    def get_code(self):
        return self.c


class StaticArray:
    def __init__(self, c):
        self.c = c
        self.c_array_def = c[:c.find('\n') + 1]
        self.ended_by_comma = False

        start_pos = self.c.find('\n')
        end_pos = len(c) - 1
        self.list = self.c[start_pos + 1:end_pos - 1].split('\n')
        while self.list[-1] == '':
            self.list.pop()
        # print("##########")
        # print(self.list[-1])
        # print("##########")
        # print(self.c_array_def)
        # print("++++++++++")
        last_idx = -1
        if self.list[last_idx][0] == '#':
            last_idx = -2
        res = re.search(r'\s*\{*([\w\d\s\|\n])+(([,\s])*([\w\d\|\n\s]*))+\}*', self.list[last_idx])
        # print(res)
        # print(self.list[-1][res.start():res.end()])

        if ((self.list[last_idx].find(',', res.end())) == -1 and 
                ((self.c_array_def == "static const ssl_trace_tbl ssl_sigalg_tbl[] = {\n") or 
                (self.c_array_def == "static const SIGALG_LOOKUP sigalg_lookup_tbl[] = {\n"))):
            self.list[last_idx] = self.list[last_idx] + ','

        # TO DO!!!!
        #print(self.c_array_def)

        self.spaces_before_item = c[start_pos + 1:re.search(r'[\S]',
                                    c[start_pos + 1:]).start() + start_pos + 1]
        # print(self.spaces_before_item)

    def p2c(self):
        items = ''.join([x + '\n' for x in self.list[:-1]])
        items += self.list[-1] + '\n' + '}'
        return self.c_array_def + items

    def append2c(self, item):
        self.list.append(self.spaces_before_item + item)

    def insert_before(self, item_before, item):
        self.list.insert(self.list.index(item_before), item)


def patch_ssl_ciph():
    Patch('patch.json')
    # filename = 'ssl_ciph.c'  # os.path.join('.', 'ssl_ciph.c')
    # with open(filename, 'r') as f:
    #     content = f.read()

    # string_for_search = 'ssl_cipher_table_cipher'
    # arr = search_array(content, string_for_search)
    # c_array = StaticArray(arr)
    # c_array.append2c('{SSL_BELTCTR, NID_belt_ctrt}')
    # print(arr)
    # obj_ = Array(arr)
    # print(obj_.items)
    # print(obj_.indent)
    # print(obj_.ended_by_comma)
    # obj_.add_item('{SSL_BELTCTR, NID_belt_ctrt}')
    # print(obj_.items)
    # content = content.replace(arr, c_array.p2c())

    # string_before = '};'
    # string_for_insert = '    {SSL_BELTCTR, NID_belt_ctrt},\n
    # {SSL_BELTDWP, NID_belt_dwpt},\n'
    # search_array(content, string_for_search)
    # content, idx = insert_string(content, string_for_search,
    #                   string_for_insert, idx, string_before)

    # with open("out.c", "w") as f:
    #     f.write(content)

    # if content[start_idx:content.find('\n', start_idx)].find('\\'):


if __name__ == '__main__':
    # filename = 'ssl_ciph.c'  # os.path.join('.', 'ssl_ciph.c')
    # with open(filename, 'r') as f:
    #     content = f.read()

    # search_macro(content, 'SSL_aCERT')
    patch_ssl_ciph()
