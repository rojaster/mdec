import traceback
from mdecbase import Service
import angr

class AngrService(Service):
    """
    angr as a service
    """
    # FIXME(alekum): This should be moved out into separate module after refactoring
    # Service should not be responsible for angr project processing, just request handling
    def _create_project(self, path: str) -> angr.Project:
        prj = angr.Project(path, auto_load_libs=False, load_debug_info=True)
        cfg = prj.analyses.CFG(normalize=True,
                             resolve_indirect_jumps=True,
                             data_references=True,
                             cross_references=True)

        prj.analyses.CompleteCallingConventions(cfg=cfg,
                                              recover_variables=True,
                                              analyze_callsites=True)
        return prj

    def _get_functions(self, prj: angr.Project, func_filter=None) -> list:
        """Get list of functions filtered by validator"""
        _default = lambda f: not(f.is_plt or f.is_simprocedure or f.alignment or f.is_syscall)
        filtered = func_filter or _default
        return [f for f in prj.kb.functions.values() if filtered(f)]

    def process(self, path: str, action_method) -> str:
        """
        Decompile all the functions in the binary located at `path`.
        """
        prj   = self._create_project(path)
        funcs = self._get_functions(prj)
        out   = [ action_method(func) for func in funcs ]
        return '\n'.join(out)

    def decompile(self, path: str) -> str:
        def decompile_action(func) -> str:
            try:
                decompiled = func.project.analyses.Decompiler(func).codegen.text
            except:
                decompiled = f"/* Decompilation of {func} failed:\n{traceback.format_exc()}\n*/"
            return decompiled
        return self.process(path, decompile_action)

    def lifting(self, path: str) -> str:
        def lifting_action(func) -> str:
            out = [f"/******************** Lifted {func.name} ********************/"]
            try:
                out += [ str(bb.vex) for bb in func.blocks ]
            except:
                out += ['Could not lift...']
            out += [f"/******************** Lifted {func.name} ********************/\n"]
            return '\n'.join(out)
        return self.process(path, lifting_action)

    def version(self) -> str:
        return '.'.join(str(i) for i in angr.__version__)
