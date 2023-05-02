import angr

def analyze(binary, start, end, avoid=None):
    # By default angr loader puts PIE executables inside the upper-half 32-bit userspace address
    # Ghidra, by default, uses a different base address.
    # Update main_opts/base_addr to use Ghidra's
    p = angr.Project(binary, main_opts={"base_addr": 0x100000})

    print(f"start {start}, end {end}, avoid {avoid}")

    state = p.factory.blank_state(
        addr=start,
        add_options={
            angr.options.LAZY_SOLVES,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    sm = p.factory.simgr(state)

    while len(sm.active) > 0:
        print(sm)

        sm.explore(find=end, avoid=avoid)
        if len(sm.found) > 0:
            print("[malwhere/angr] found solution")
            return sm.found[0]

    print("[malwhere/angr] end")
    return None
