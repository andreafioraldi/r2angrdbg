import r2pipe
import r2angrdbg

r2 = r2pipe.open("ais3_crackme")
r2angrdbg.init(r2)

r2.cmd("aaa")
r2.cmd("ood DUMMY")
r2.cmd("db 0x004005f9")
r2.cmd("dc")

sm = r2angrdbg.StateManager()
sm.sim(sm["rax"], 100)

m = sm.simulation_manager()
m.explore(find=0x00400602, avoid=0x0040060e)

conc = sm.concretize(m.found[0])
for addr in conc:
    print "0x%x ==>" % addr, repr(conc[addr])

sm.to_dbg(m.found[0])

print r2.cmd("x 100 @ rax")
r2.cmd("dc")

