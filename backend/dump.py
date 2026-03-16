import dpkt.pcapng
import inspect

with open('pcapng_src.py', 'w') as f:
    f.write(inspect.getsource(dpkt.pcapng.Reader))
