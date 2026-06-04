import config

class OperationCounter:
    def __init__(self, Th: int = 0, Tpa: int = 0, Tpad: int = 0, Ted: int = 0, Tb: int = 0):
        self.Th = Th
        self.Tpa = Tpa
        self.Tpad = Tpad
        self.Ted = Ted
        self.Tb = Tb

def count_vessel_operations() -> OperationCounter:
    # 11 Th + 4 Tpa
    return OperationCounter(Th=11, Tpa=4)

def count_hap_operations() -> OperationCounter:
    # 5 Th + 3 Tpa
    return OperationCounter(Th=5, Tpa=3)

def count_cs_operations() -> OperationCounter:
    # 9 Th + 4 Tpa
    return OperationCounter(Th=9, Tpa=4)

def compute_total_cost(vessel_ops: OperationCounter, hap_ops: OperationCounter, cs_ops: OperationCounter) -> float:
    # Compute individual entity costs
    vessel_cost = (
        vessel_ops.Th * config.TH_DEVICE +
        vessel_ops.Tpa * config.TPA_DEVICE +
        vessel_ops.Tpad * config.TPAD_DEVICE +
        vessel_ops.Ted * config.TED_DEVICE +
        vessel_ops.Tb * config.TB_DEVICE
    )
    
    hap_cost = (
        hap_ops.Th * config.TH_HAP +
        hap_ops.Tpa * config.TPA_HAP +
        hap_ops.Tpad * config.TPAD_HAP +
        hap_ops.Ted * config.TED_HAP +
        hap_ops.Tb * config.TB_HAP
    )
    
    cs_cost = (
        cs_ops.Th * config.TH_SERVER +
        cs_ops.Tpa * config.TPA_SERVER +
        cs_ops.Tpad * config.TPAD_SERVER +
        cs_ops.Ted * config.TED_SERVER +
        cs_ops.Tb * config.TB_SERVER
    )
    
    return vessel_cost + hap_cost + cs_cost

def print_cost_table() -> None:
    v_ops = count_vessel_operations()
    h_ops = count_hap_operations()
    c_ops = count_cs_operations()
    
    v_cost = v_ops.Th * config.TH_DEVICE + v_ops.Tpa * config.TPA_DEVICE
    h_cost = h_ops.Th * config.TH_HAP + h_ops.Tpa * config.TPA_HAP
    c_cost = c_ops.Th * config.TH_SERVER + c_ops.Tpa * config.TPA_SERVER
    total = compute_total_cost(v_ops, h_ops, c_ops)
    
    print("-" * 50)
    print(f"{'Entity':<15} | {'Th count':<8} | {'Tpa count':<9} | {'Cost (ms)':<10}")
    print("-" * 50)
    print(f"{'Vessel':<15} | {v_ops.Th:<8} | {v_ops.Tpa:<9} | {v_cost:<10.3f}")
    print(f"{'HAP':<15} | {h_ops.Th:<8} | {h_ops.Tpa:<9} | {h_cost:<10.3f}")
    print(f"{'Control Station':<15} | {c_ops.Th:<8} | {c_ops.Tpa:<9} | {c_cost:<10.3f}")
    print("-" * 50)
    print(f"{'Total Computation Cost':<39} | {total:<10.3f} ms")
    print("-" * 50)
