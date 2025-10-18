def apply_constraint(state, expr, init_val, **kwargs):
    return


def specify_sinks():
    maps = {'srand': ['n']}
    return maps


def specify_sources():
    checkpoints = {'time': 0}
    return checkpoints


def get_results(reports):
    results_dict = {}
    
    for r in reports:
        key = hex(r.bbl)
        results_dict[key] = r.bbl_history
        
    return results_dict



def save_results(reports):
    for r in reports:
        with open(f"ArbiterReport_{hex(r.bbl)}", "w") as f:
            f.write("\n".join(str(x) for x in r.bbl_history))