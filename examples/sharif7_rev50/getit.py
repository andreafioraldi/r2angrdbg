import r2pipe
import r2angr

r2 = r2pipe.open("getit")
r2angr.init(r2)

r2angr.set_memory_type(r2angr.USE_CLE_MEMORY)

r2.cmd("aaa")
r2.cmd("ood")
r2.cmd("db main")
r2.cmd("dc")

flag_addr = 0x6010e0
stop_addr = 0x4008c8

sm = r2angr.StateManager()

m = sm.simulation_manager()
m.explore(find=stop_addr)

flag = m.found[0].memory.load(flag_addr, 50)

print m.found[0].solver.eval(flag, cast_to=str)
