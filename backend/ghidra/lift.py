# @Cleanup(alekum): Re-used some functionality from dump.py
# Refine code to extract common part, also reminder that Ghidra
# use Jython...no python3 features...
# Dump raw Pcode
import traceback

out = open('out.c', 'w')
listing = currentProgram.getListing()
for func in currentProgram.getFunctionManager().getFunctions(True):
    try:
        out.write("Function: %s @ 0x%s\n" % (str(func.getName()), str(func.getEntryPoint())))
        func_body = func.getBody()
        opiter = listing.getInstructions(func_body, True)
        while opiter.hasNext():
            op = opiter.next()
            raw_pcode = op.getPcode()
            out.write("\t%s\n" % str(op))
            for entry in raw_pcode:
                out.write("\t\t%s\n" % str(entry))
        out.write('\n')
    except:
        out.write(traceback.format_exc())
        out.write('Failed to decompile %s\n' % str(func))
