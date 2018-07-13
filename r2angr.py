import r2pipe
import base64

from angrdbg import *


class R2Debugger(Debugger):
    def __init__(self, r2):
        self.r2 = r2

    def _get_vmmap(self):
        return None

    def _get_sections(self):
        return None
    
    # -------------------------------------
    def before_stateshot(self):
        self.vmmap = self._get_vmmap()
        sections = self._get_sections()

        for start, end, name in sections:
            if name == load_project().arch.got_section_name:
                self.got = (start, end)
            elif name == ".plt":
                self.plt = (start, end)

    def after_stateshot(self, state):
        pass
    # -------------------------------------

    def is_active(self):
        return gdb.selected_thread() is not None

    # -------------------------------------
    def input_file(self):
        path = self.r2.cmdj("dmj")[0]["file"]
        return open(path, "rb")

    def image_base(self):
        if self.base_addr is None:
            self.base_addr = int(self.r2.cmd("e bin.baddr"))
        return self.base_addr

    # -------------------------------------
    def get_byte(self, addr):
        try:
            return ord(self.r2.cmd("pr 1 @ %d" % addr))
        except BaseException:
            return None

    def get_word(self, addr):
        try:
            return struct.unpack(
                "<H", self.r2.cmd("pr 2 @ %d" % addr))[0]
        except BaseException:
            return None

    def get_dword(self, addr):
        try:
            return struct.unpack(
                "<I", self.r2.cmd("pr 4 @ %d" % addr))[0]
        except BaseException:
            return None

    def get_qword(self, addr):
        try:
            return struct.unpack(
                "<Q", self.r2.cmd("pr 8 @ %d" % addr))[0]
        except BaseException:
            return None

    def get_bytes(self, addr, size):
        try:
            return self.r2.cmd("pr %d @ %d" % (size, addr))
        except BaseException:
            return None

    def put_byte(self, addr, value):
        self.put_bytes(addr, chr(value))

    def put_word(self, addr, value):
        self.put_bytes(addr, struct.pack("<H", value))

    def put_dword(self, addr, value):
        self.put_bytes(addr, struct.pack("<I", value))

    def put_qword(self, addr, value):
        self.put_bytes(addr, struct.pack("<Q", value))

    def put_bytes(self, addr, value):
        self.r2.cmd("w6d %s @ %d" % (base64.b64encode(value), addr))

    # -------------------------------------
    def get_reg(self, name):
        if name == "efl":
            name = "eflags"
         return int(self.r2.cmd("dr?" + name), 16)

    def set_reg(self, name, value):
        if name == "efl":
            name = "eflags"
        self.r2.cmd("dr %s = %d" % (name, value))

    # -------------------------------------
    def step_into(self):
        self.r2.cmd("ds")

    def run(self):
        self.r2.cmd("dc")

    def wait_ready(self):
        pass

    def refresh_memory(self):
        pass

    # -------------------------------------
    def seg_by_name(self, name):
        return None

    def seg_by_addr(self, addr):
        return None

    def get_got(self):  # return tuple(start_addr, end_addr)
        return self.got

    def get_plt(self):  # return tuple(start_addr, end_addr)
        return self.plt

    # -------------------------------------
    def resolve_name(self, name):  # return None on fail
        return None


r2 = r2pipe.open('#!pipe')

register_debugger(R2Debugger(r2))

