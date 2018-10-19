import r2pipe
import r2angrdbg

r2 = r2pipe.open("ais3_crackme")
r2angrdbg.init(r2)

r2.cmd("aaa")
r2.cmd("ood DUMMY")
r2.cmd("db 0x004005f9")
r2.cmd("dc")

sm = r2angrdbg.StateManager()
key = sm.sim(sm["rax"], 100)
argv1, size = sm.get_symbolic(key)
initial_state = sm.get_state()

initial_state.add_constraints(argv1.chop(8)[0] == b'a')
initial_state.add_constraints(argv1.chop(8)[1] == b'i')
initial_state.add_constraints(argv1.chop(8)[2] == b's')
initial_state.add_constraints(argv1.chop(8)[3] == b'3')
initial_state.add_constraints(argv1.chop(8)[4] == b'{')

m = sm.simulation_manager()
m.explore(find=0x00400602, avoid=0x0040060e)
print(m)
conc = sm.concretize(m.found[0])
for addr in conc:
    print ("0x%x ==> %s" % (addr, repr(conc[addr])))

sm.to_dbg(m.found[0])

print (r2.cmd("x 100 @ rax"))
r2.cmd("dc")

