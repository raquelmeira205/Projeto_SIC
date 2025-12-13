from pydbus import SystemBus

bus = SystemBus()
print("Bus type:", type(bus))
print("Dir bus:", dir(bus))

try:
    print("Does register_object exist?", hasattr(bus, 'register_object'))
except:
    pass
