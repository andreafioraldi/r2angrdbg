import r2pipe
import r2angr

r2 = r2pipe.open("ais3_crackme", ["-d"])
r2angr.init(r2)

r2.cmd("aaa")
r2.cmd("db 0x004005f9")
r2.cmd("dc")

sm = r2angr.StateManager()
raw_input()
sm.sim(sm["rax"], 100)

m = sm.simulation_manager()
m.explore(find=0x00400602, avoid=0x0040060e)

print m

