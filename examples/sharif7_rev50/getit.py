from r2angrdbg import *

r2 = r2pipe.open("getit")
init(r2)

set_memory_type(USE_CLE_MEMORY)

r2.cmd("aaa")
r2.cmd("ood")
r2.cmd("db main")
r2.cmd("dc")

flag_addr = 0x6010e0
stop_addr = 0x4008c8

sm = StateManager()

m = sm.simulation_manager()
m.explore(find=stop_addr)

flag = m.found[0].memory.load(flag_addr, 50)

print m.found[0].solver.eval(flag, cast_to=str)
